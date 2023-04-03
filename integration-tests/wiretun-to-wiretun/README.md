# Test Case: WireTun to WireTun

## Setup

- [peer1](./peer1) is a WireTun instance running on the host machine with NativeTun.
- [peer2](./peer2) is a WireTun instance running on the host machine with MemoryTun which will not create any tun device.
- [tester](./tester) will run test cases to verify the connectivity between peer1 and peer2.
