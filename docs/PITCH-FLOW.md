# Presentation Flow — 9-Pillar Evaluation Matrix

**Team:** Git with It · **Team ID:** 261
**PS 26153 (NTRO)** — AI based Network Attack Forecasting from Network Traffic Data

Ye document ek hi cheez ke liye hai: **har pillar deliberately hit ho**, ittefaq
se nahi. Judges 9 alag cheezein score karte hain — agar aap sirf demo achha
dikha doge to 3 pillar mil jaayenge aur 6 chhoot jaayenge.

---

## Pehle ek nazar — kaunsa pillar kahan milta hai

| # | Pillar | Kahan earn hota hai | Kaun bolta hai |
|---|---|---|---|
| 1 | Understanding of Problem Statement | Opening, 0:00–1:30 | Suyash |
| 2 | Innovation & Novelty | "Cut the traffic off" moment, 1:30–3:00 | Suyash |
| 3 | Technical Feasibility | Architecture + benchmark, 3:00–4:15 & 7:00–8:00 | Suyash + Shivam |
| 4 | Impact & Scalability | Closing block, 8:00–9:00 | Yuvan |
| 5 | Prototype / PoC | Live dashboard, 4:15–7:00 | Tanay |
| 6 | Technology Competency | Stack + debugging stories, Q&A | Sab, apne area mein |
| 7 | Implementation & Live Demo | Play + upload, 4:15–7:00 | Tanay + Yuvan |
| 8 | Presentation & Pitch Quality | Poore time | Suyash leads |
| 9 | Teamwork & Role Distribution | Opening 20 sec + Q&A handoffs | Sab |

> **Sabse zyada chhootne wale pillar: 4, 6, 9.** Teams demo mein kho jaate hain
> aur impact, competency aur teamwork bina bole nikal jaate hain. Neeche har ek
> ke liye jagah fix ki hai.

---

## Minute-by-minute flow (10 minute + Q&A)

| Time | Kya | Pillar | Kaun |
|---|---|---|---|
| 0:00–0:20 | Team intro, role division | **9** | Suyash |
| 0:20–1:30 | Problem: detection vs forecasting | **1** | Suyash |
| 1:30–3:00 | Solution + kya naya hai | **2** | Suyash |
| 3:00–4:15 | Architecture + tech stack | **3, 6** | Suyash |
| 4:15–5:45 | Live demo: replay, kill chain, explain | **5, 7** | Tanay |
| 5:45–6:30 | Topology + upload | **5, 7** | Tanay → Yuvan |
| 6:30–7:00 | "Hamesha 100% kyun?" — constructed sample | **1, 3** | Yuvan |
| 7:00–8:00 | Benchmarks + teen honest findings | **3** | Shivam |
| 8:00–9:00 | Impact, scale, deployment | **4** | Yuvan |
| 9:00–9:30 | Close: chaar line | **8** | Suyash |
| Q&A | Handoff by area | **6, 9** | Sab |

---

## Pillar 1 — Understanding of Problem Statement

**Kahan:** 0:20–1:30, aur phir 6:30 pe dobara (jab dataset ki limitation batate ho).

**Bolna:**

> "PS kehta hai *forecast*, *detect* nahi. Ye farak poora project decide karta hai.
>
> Aaj ke IDS — Suricata, Zeek — signature aur rule pe chalte hain. Wo batate hain
> **kya ho chuka**. Analyst ko alert tab milta hai jab attack ho chuka hota hai.
>
> Humein jo chahiye tha wo alag sawaal hai: **ye host agle 10 minute mein kahan
> hoga?** Uske liye traffic classify karna kaafi nahi — network ki state kaise
> badalti hai, wo seekhna padta hai."

**Ye bhi bol dena (understanding yahin dikhti hai):**

> "PS ne flow-level aur packet-level dono maange the — humne 39 flow features aur
> 23 packet features banaye. MITRE ATT&CK stage mapping maangi thi — 5 stages.
> Explainability maangi thi, black box nahi — teen channel diye. Aur fully
> offline, no cloud API — poora system CPU pe chalta hai."

> **Trap:** PS ko "network security ka problem" bol ke general baat mat karna.
> Uske exact words uthao — forecast, ATT&CK, explainable, offline.

---

## Pillar 2 — Innovation & Novelty

**Kahan:** 1:30–3:00. Ye pitch ka sabse important 90 second hai.

**Bolna — chaar step mein:**

> "1. Traffic ko 60-second windows mein todte hain. Har window ek host ka
> 39-feature snapshot hai.
>
> 2. Model transitions seekhta hai — is state ke baad aam taur pe kaunsa state
> aata hai.
>
> 3. Phir **hum traffic dikhana band kar dete hain.** Model ko kuch nahi milta.
>
> 4. Aur wo agle 10 state **khud banata hai**. Har imagined state pe hum poochhte
> hain — risk kya hai, ATT&CK stage kya hai."

**Step 3 pe rukna.** Wahi novelty hai. Classifier ye kar hi nahi sakta.

**Novelty ka proof (ye zaroor bolna):**

> "Aur ye claim humne testable banaya hai. Humare test suite mein ek assertion
> hai: agar sirf imagination loss se backprop karo, to **encoder ka gradient zero
> aana chahiye** — kyunki imagination mein encoder use hi nahi hota. Agar wo test
> fail ho, matlab hum cheat kar rahe hain. Wo pass hota hai."

> **Trap:** "world model" bol ke aage mat badhna. Judge ko ye phrase pata ho
> sakta hai. **"Traffic band kar dete hain"** wala step bolo — wo yaad rehta hai.

---

## Pillar 3 — Technical Feasibility

**Kahan:** 3:00–4:15 (architecture) aur 7:00–8:00 (benchmarks).

**Architecture ek line mein:**

> "Ingest → 39+23 features → 60-second state cells → encoder+GRU → prior rollout
> → teen heads → dashboard. Slide pe poora diagram hai."

**Feasibility ke paanch point:**

| | |
|---|---|
| Technical | 1,38,398 parameters, CPU-only. GPU nahi chahiye. |
| Financial | Zero licence cost, sab open source |
| Operational | NetFlow/IPFIX jo enterprise already export karte hain |
| Legal | Data network se bahar jaata hi nahi |
| Social | Final decision analyst ka, model sirf ranking deta hai |

**Benchmarks (Shivam):**

> "Split time se kiya, randomly nahi — har capture ke past pe train, future pe
> test. Baselines ko bilkul wahi features, wahi scaler, wahi labels diye.
>
> Stage forecast +3 windows pe hum 0.647 dete hain, 'maan lo kuch nahi badlega'
> wala baseline 0.478. 10 mein se 9 horizons pe hum aage hain."

> **Trap:** Detection F1 ko badha-chadha ke mat bolna. Wo 0.979 vs 0.977 — tie
> hai. Khud bol do, judge ke poochhne se pehle. Neeche Finding 1 mein hai.

---

## Pillar 4 — Impact & Structural Scalability

**Kahan:** 8:00–9:00. **Ye sabse zyada chhootne wala pillar hai** — demo ke baad
log seedha close kar dete hain.

**Bolna (Yuvan):**

> "Kaun use karega — SOC analysts ko alert flood ki jagah ranked queue milta hai.
> Critical infrastructure: power, banking, telecom, transport. CERT-In jaise
> national response teams.
>
> Scale: inference batched hai — ek capture ke saare hosts ek pass mein. 2,836
> hosts wale capture pe first load ke baad sub-second triage hai.
>
> Deployment: naya hardware nahi chahiye. Jo NetFlow already export ho raha hai
> wahi input hai. Ek Python process, ek checkpoint file. Air-gapped network mein
> bhi chalega kyunki kuch bahar jaata hi nahi."

> **Trap:** "lakhs of hosts pe scale karega" mat bolna — humne test nahi kiya.
> Jo test kiya hai wo number bolo: **2,836 hosts**. Aur aage ke liye kaho
> "distributed karna seedha hai, par humne measure nahi kiya."

---

## Pillar 5 — Prototype / Proof of Concept

**Kahan:** 4:15–7:00. Dashboard khula rakhna, slides pe wapas mat jaana.

Ye pillar **prototype ka asli hona** score karta hai — kitna complete hai, kitna
kaam karta hai. Demo ka order Pillar 7 mein hai.

**Bolne ki line:**

> "Ye mock nahi hai. Real CTU-13 data, 2,58,229 network states, 13 captures.
> Model abhi is laptop pe chal raha hai — koi cloud call nahi."

---

## Pillar 6 — Technology Competency

**Kahan:** Q&A mein zyada, aur architecture ke waqt thoda.

Ye pillar tab milta hai jab aap **kyun** ka jawab de paate ho, sirf **kya** ka
nahi. Har member apne area ke 2-3 numbers yaad rakhe.

**Sabse strong competency signal — debugging stories:**

> **"Pandas 3.0 mein timestamps default `datetime64[us]` hain. Humara code
> nanoseconds maan raha tha, to saare timestamps 1000 guna galat aa rahe the.
> `.dt.as_unit('ns')` se fix kiya."**

> **"Model selection humne BCE loss pe nahi, validation average precision pe
> kiya. Data 0.8% positive hai — wahan loss galat model chun leta hai."**

> **"Scapy ka poora stack slow hai, isliye `RawPcapReader` + `struct` use kiya —
> packet objects banaye bina headers parse karte hain. 4 lakh packets 12 second
> mein."**

> **Trap:** Agar kisi member se uske area ka sawaal aaye aur jawab na aaye —
> bluff mat karna. Bolna: *"Wo hissa maine implement nahi kiya, Suyash ne kiya."*
> Galat jawab pakda jaata hai, "maine wo part nahi kiya" nahi.

---

## Pillar 7 — Implementation & Live Demo

**Kahan:** 4:15–7:00. Exact click order:

**1. Host list (10 sec)**
Scenario 1. Sabse upar `147.32.84.165` — 100%. Baaki 0%.
> "Model ne wahi machine pakdi jisme asli malware tha."

**2. Play dabao (60 sec) — sabse strong moment**
> "Divider ke baayein model traffic dekh raha hai. Daayein kuch nahi — har point
> wo khud bana raha hai."

Play ke dauraan **teen cheezon pe ungli rakhna:**
- playhead baayein se daayein safar karta hai
- neeche **kill chain** ka NOW/PREDICTED card live badalta hai
- **~12 second pe ek tone bajega** — wahi stage change hai. Us beat pe kaho:
  *"Ye sun rahe ho? model ne abhi stage change detect kiya."*

> Normal speed pe poora capture ~1 minute. Time kam ho to **Fast** (~20 sec)
> ya 15 second baad Pause.

**3. Pehle hi bol dena (warna judge poochhega):**
> "Probability 100% pe flat hai. Jo badal raha hai wo **line ka rang** hai — wahi
> ATT&CK stage hai."

**4. Explainability (30 sec)**
Feature attribution + temporal attention.
> "Model ke paas 120 minute ka past tha. Barabar baantta to har minute ko 0.8%
> milta. Usne 25% attention sirf 5 minute pe daala — sabse zyada 23 minute pehle
> wale pe, average se 7.7 guna."

**5. Topology tab (30 sec)**
3D scene. Scroll karke zoom, ek node pe click.
> "Node ka rang humara model ka conclusion hai, edge ka rang dataset ka label.
> Isliye hara node laal edges ke saath dikhe to wo host humara model **miss** kar
> gaya. Humne chhupaya nahi."

**6. Benchmark tab (20 sec)**
Horizon chart pe cursor ghumao — har point ke exact numbers.

**7. Upload — "hamesha 100% kyun?" (30 sec)** ← Pillar 1 + 3 dobara
`data/samples/host-becomes-infected.csv` upload karo.
> "Ye file humne **banayi** hai — dataset mein aisa host tha hi nahi. Ek saaf
> workstation ka traffic, phir usi IP pe botnet traffic. Ab dekhiye — 38 window
> flat, phir risk chadhta hai. Aur surprise channel **theek us window pe** +6σ
> spike karta hai jab traffic badalta hai, risk head 10 window baad commit karta
> hai. Isiliye humne dono channel rakhe hain."

> **Trap:** File constructed hai — **pehle hi bolna**. Baad mein pata chalna bahut
> bura hota hai.

---

## Pillar 8 — Presentation & Pitch Quality

Ye pillar alag block mein nahi milta — poore time milta hai.

**Chaar cheezein jo score badalti hain:**

1. **Ek waqt mein ek banda bolta hai.** Beech mein add-on mat karna. Handoff saaf
   ho: *"Iska detail Shivam batayega."*
2. **Slide padhna nahi hai.** Slide pe diagram hai; aap uska matlab bolo.
3. **Numbers exact bolna.** "kaafi accha" ki jagah "0.647 vs 0.478".
4. **Limitations khud bolna.** Judge ke poochhne se pehle bola hua limitation
   confidence dikhata hai; poochhne ke baad bola hua bahana lagta hai.

**Closing chaar line (Suyash, 9:00–9:30):**

> "Ek — hum classify nahi karte, network ki state aage chalate hain.
> Do — detection mein hum baseline ke barabar hain, aur forecasting mein 10 mein
> se 9 horizons pe aage.
> Teen — har alert ke saath teen explanation hain, black box nahi.
> Chaar — sab kuch offline chalta hai, is laptop pe, abhi."

---

## Pillar 9 — Teamwork & Role Distribution

**Kahan:** Opening ke 20 second, aur phir har Q&A handoff pe.

**Opening line (Suyash):**

> "Main Suyash, team lead — maine world model aur architecture pe kaam kiya. Team
> ke baaki paanch: data pipeline, evaluation, dashboard, backend, aur MITRE
> mapping. Har area ka owner yahan hai — jo detail chahiye poochh lijiye."

**Role map:**

| Member | Area | Q&A mein kya own karta hai |
|---|---|---|
| Suyash Shukla | Team Lead · World Model | RSSM, imagination rollout, architecture |
| Tanmay Kumar Sinha | Data Pipeline & Features | CTU-13 ingest, 39+23 features, windows |
| Shivam Kumar Tripathi | Evaluation & Benchmarks | splits, baselines, saare numbers |
| Tanay | Dashboard & Visualisation | replay, topology, kill chain |
| Yuvan Laxmanan | Backend & Deployment | FastAPI, upload, offline deployment |
| Vaishnavi Tripathi | MITRE Mapping & Explainability | 5 stages, IG, attention |

> **Trap:** Agar sirf ek banda poore time bole to Pillar 9 zero ho jaata hai —
> chahe demo kitna bhi accha ho. **Har member ko kam se kam ek baar bolna hai.**
> Jo blocks upar assign kiye hain, wahi kaafi hain.

---

## Teen honest findings — Pillar 3 aur 8 dono ke liye

Ye tab bolna jab judge deep jaaye, ya 7:00–8:00 wale block mein.

**Finding 1 — Humne apne hi code mein cheating pakdi**
> "Ek metadata flag — `has_packet_features` — perfect label proxy ban gaya tha,
> kyunki humare paas PCAP sirf botnet traffic ka tha. F1 0.23 se 0.98 ho gaya jab
> hataya. Ye humne khud audit mein pakda."

**Finding 2 — Dataset mein pre-infection baseline hai hi nahi**
> "2,58,229 windows check kiye. Infected hosts ka **ek bhi clean window nahi**.
> Isiliye probabilities calibrated nahi hain — 1,530 hosts mein har ek ya ~100%
> hai ya <5%. Aur isiliye humne binary detection ko main task nahi banaya."

**Finding 3 — Do channels ulte fail hote hain**
> "Supervised head sustained activity pe kaam karta hai, surprise channel short
> bursts pe. Upload wale demo mein ye dikha — surprise us window pe fire hua,
> risk head 10 window baad. Dono ulte hain, isliye dono lagaye. Milake 30 mein se
> 28 host, 4.9% false alarms pe."

---

## Numbers — ek jagah

| | |
|---|---|
| Network states | 2,58,229 |
| Captures | 13 (CTU-13, CC BY) |
| Model | 1,38,398 parameters, CPU-only |
| Features | 39 flow + 23 packet, 60-second windows |
| Detection F1 | 0.979 (baseline 0.977 — tie) |
| False positive rate | 0.0009 |
| Stage forecast +3 | 0.647 (baseline 0.478) |
| Horizons jeete | 9 of 10 |
| Hosts caught | 28 of 30, 4.9% false alarms |
| Unseen families | F1 0.874, ROC-AUC 0.982 |
| PCAP throughput | 4 lakh packets → 18,271 flows → 12 sec |
| Training | 12 epochs, early stop (best epoch 10) |

---

## Aakhri check — nikalne se pehle

- [ ] Server chal raha hai, `localhost:8000` khula hai
- [ ] Scenario 1 pre-loaded, host `147.32.84.165` selected
- [ ] Sound toggle 🔊 on hai (ya jaan-boojh ke off, agar room audio kharab ho)
- [ ] `data/samples/host-becomes-infected.csv` ka path pata hai
- [ ] Deck ki PDF bhi khuli hai (backup, agar projector PPT na le)
- [ ] Har member ko apne 2-3 numbers yaad hain
