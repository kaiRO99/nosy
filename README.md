# nosy
A nosy network monitor that checks for video calls. 

Uses UDP flows longer than 15 seconds, over 20 packets in each direction, and has an up to down ration of around 1:3 or 3:1. 

Classifies as videos above 500 kbps, audio below 150 kbps

My goal is to connect it to a "Live" light, so whenever someone on my network starts a meeting (e.g., teams, zoom), it lights up. Requires capturing at router.

## Roadmap
- [x] capture udp packets
- [ ] classify packets to detect video
- [ ] make cli
- [ ] write tests
- [ ] documentation
