### To-Do
---
- Channel Switch Announcement (CSA) Frame 송신
  - 기능: AP가 Client에게 Network가 서비스 중인 Channel이 변경되었다고 알려 Client가 동작 Channel을 전환하도록 함
  - 목적: Evil Twin AP를 사용한 중간자 공격 시 Client와 원본 AP의 Frame이 서로에게 전달되면 안 되므로, 서로 다른 Channel에서 동작하여 무선 네트워크상에서 서로의 Frame을 보지 못하게 하기 위함.
  - [Input] AP_MAC, Client_MAC, ...
  - [Output] 성공 여부

- Rogue AP 구현
  - 필요 기능:
    - 새로운 Rogue AP 생성, 활성화/비활성화, 네트워크 공개 여부(Beacon Frame 송신 여부) 선택, Channel 변경, 특정 유형 Frame을 전송 지연/재전송 등
  - [생성 Input] ssid, bssid, channel, crypto, ...

- 4-way Handshake 감지
  - 기능: sniff 수행 중 4-way Handshake(EAPOL-Key) 유형의 프레임이 수집됨을 감지
  - 목적: 암호화 연결 수립을 위해 주고받는 정보 수집(ANonce, SNonce, ...), 재전송 공격
  - 추가적인 용도: Deauth 공격 이후 재연결 감지
  - 
- GUI
  - 구현된 기능을 바탕으로 사용자 인터페이스 구성
  - 여러 기능 비동기적으로 toggle(켜고 끄기) 가능하게 -> Qthread 등 활용
