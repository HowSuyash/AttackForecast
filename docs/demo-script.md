# Demo video script — 2 minutes

Target: 115 seconds of narration, leaving headroom. Record at 1920×1080 with
the dashboard already open and the model loaded, so nothing spins on camera.

## Before you record

```bash
python -m uvicorn server.app:app --port 8000
```

Then open `http://127.0.0.1:8000`, pick **Scenario 1 — Neris**, and wait for the
host ranking to finish once. It is cached afterwards, so every click in the
recording is instant. Disconnect from wifi before recording — the page runs
fully offline, and showing that costs nothing.

---

## 0:00–0:15 · The gap

> "A conventional intrusion detector looks at one flow and calls it benign or
> malicious. But an infiltration isn't one packet — it's a process. Ports get
> probed in sequence, a command channel opens, then data leaves.
> We built a world model: instead of classifying traffic, it learns how network
> state evolves, and simulates it forward."

**On screen:** the dashboard, host list visible on the left.

---

## 0:15–0:35 · Triage

> "Every host in the capture is ranked by forecast risk. Top of the list is
> 147.32.84.165 — which is in fact the compromised machine in this CTU-13
> scenario. The rest of the network sits near zero."

**On screen:** hover the top host, let the risk pill and the low scores below it
read clearly. Click the host.

---

## 0:35–1:10 · The forecast, played back — the core of the demo

> "Left of this divider the model is watching real traffic. Right of it, it sees
> nothing at all — each step is rolled forward through the learned prior, the
> model imagining the next state from the last one."
>
> *(press Play)*
>
> "Now watch it happen. Every minute the model emits a forecast, then time
> advances past it and you can see whether it was right. And this strip is the
> whole capture at a glance — blue is reconnaissance, red is exfiltration. The
> host scans for nine minutes, then starts sending spam."

**On screen:** press **▶ Play** and let it run. This is the segment that earns
the demo — a static chart makes you *assert* that the model forecasts; replay
makes the viewer *watch* it. Let the kill-chain strip fill in underneath.

Then scroll to the MITRE kill chain and pause a beat on the "now" divider.

---

## 1:05–1:30 · Why it thinks so

> "No black box. Three explanations for every prediction: which measurements
> drove the score, which earlier windows the attention actually used, and — most
> usefully — what the model expects the traffic itself to do. Here it is saying
> distinct destination ports will grow from twelve to two hundred and forty.
> That's a port scan, six minutes before it happens."

**On screen:** attribution bars → attention chart → the predicted state-change
table. Let the state-change row sit on screen for two seconds.

*(Replace the numbers with whatever the recorded run actually shows.)*

---

## 1:25–1:35 · The network, seen whole

> "And this is the network it lives in. The red node is the compromised
> machine; every red line is a malicious connection. Three and a half thousand
> hosts in this capture, and the bot reached eighteen hundred and fifty of them."

**On screen:** the **Topology** tab. One beat — the starburst explains itself.
Direct link if you want to open straight to it: `http://127.0.0.1:8000/#topology`

---

## 1:35–1:50 · Bring your own traffic

> "It isn't tied to the dataset. Upload a PCAP and it reconstructs flows from
> raw packets, computes both flow-level and packet-level features — TTL
> variance, TCP window, retransmissions, scan signatures — and runs the same
> forecast. Everything you've seen runs offline: no cloud, no API."

**On screen:** click Upload, choose `data/raw/neris-botnet.pcap`, let the ingest
line appear. Keep this segment tight — if the parse takes more than a few
seconds, cut to the finished result.

---

## 1:50–2:00 · Honest close

> "And one result we report rather than hide: in CTU-13 the infected hosts are
> malicious in every window they appear, so binary 'will it be attacked' is
> nearly degenerate on this data. Kill-chain progression is the signal that
> actually generalises — and that's what we forecast."

**On screen:** the Benchmark tab.

---

## Recording notes

- Screen-record at 30 fps; the canvas charts have no animation to smear.
- Do not narrate the architecture diagram — the slides do that. The video's job
  is to show the thing working.
- If a take runs long, cut the upload segment first. The forecast panel and the
  explanation panel are the two that must survive.
