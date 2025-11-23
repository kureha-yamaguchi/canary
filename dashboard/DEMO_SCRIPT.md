# Project Canary - Demo Script

## The Pitch (30 seconds)

> "AI agents are being weaponized. We built a honeypot intelligence platform that measures what they can do, identifies who they are, and predicts what they'll do next—enabling proactive defense instead of reactive response."

---

## Act 1: The Problem (1 minute)

**Narrative:** AI agents are increasingly being used for malicious purposes—automated vulnerability scanning, credential stuffing, and sophisticated attack chains. Traditional security tools can't distinguish between humans, scripts, and AI agents, making attribution and prediction impossible.

**Demo:** Show any recent news about AI agent-based attacks or discuss the threat landscape.

---

## Act 2: Honeypots as Capability Sensors (2 minutes)

**Page:** Live Attacks (`/`)

**Narrative:**
> "We deploy honeypots with varying complexity levels across websites. These aren't just decoys—they're capability sensors. By measuring which honeypots get triggered, we can benchmark what AI agents can actually do in the wild."

**Demo Points:**
1. Show the live attack feed with real-time events
2. Point out the different event types (clicks, navigation, form interactions)
3. Highlight timing patterns visible in the event stream
4. Explain: "Each interaction tells us something about the attacker's capabilities"

**Key Question Answered:** "What's happening right now?"

---

## Act 3: Attribution - Who Is Attacking? (3 minutes)

**Page:** Agent Analysis (`/agent-trajectory`)

**Narrative:**
> "This is where it gets interesting. We have internal red-team AI agents that create baseline behavioral fingerprints. By comparing external attackers to these baselines, we can determine if they're human, a simple script, or an AI agent—and even identify which model."

**Demo Points:**
1. Start a live monitoring session
2. Show behavioral features being extracted:
   - **Timing:** Average time between actions, burst detection
   - **Click patterns:** Grid alignment (scripts), spread (humans), focused (AI)
   - **Engagement:** Scroll behavior, time on page, element interaction
3. Highlight the classification probabilities updating in real-time
4. Show model attribution (GPT-4 vs Claude vs Llama based on timing)
5. Click "Reveal Actual Attacker" to show ground truth

**Technical Detail:**
- Humans: Variable timing (1-10s), high click spread, scroll/reading behavior
- Scripts: Consistent timing (<100ms variance), grid-aligned clicks, no engagement
- AI Agents: Moderate timing with "thinking" pauses, goal-oriented navigation

**Key Question Answered:** "Who is attacking us?"

---

## Act 4: Prediction - What Will They Do Next? (3 minutes)

**Page:** TTP Prediction (`/ttp-prediction`)

**Narrative:**
> "Once we know we're dealing with an AI agent, we can predict its next moves. Our red-team agents have generated known attack trajectories that we use as reference patterns. By matching observed behavior to these patterns, we can predict which TTPs will be used next."

**Demo Points:**
1. Click "Run Demo" to show a sample trajectory
2. Walk through the three columns:
   - **Left:** Attack trajectory (the events we've captured)
   - **Middle:** Predicted TTPs with confidence scores and evidence
   - **Right:** Recommended mitigations prioritized by urgency
3. Highlight the "Next likely technique" predictions
4. Show how mitigations are mapped to predicted techniques
5. Point out pattern matching to known red-team attack chains

**Value Proposition:**
> "Instead of waiting for an attack to complete and then doing forensics, we can predict the attack chain and deploy mitigations proactively."

**Key Question Answered:** "What will they do next, and how do we stop them?"

---

## Act 5: The Complete Picture (1 minute)

**Page:** MITRE Matrix (`/matrix-map`)

**Narrative:**
> "All of this maps back to the MITRE ATT&CK framework. We're building an open-source knowledge base of AI agent attack patterns—real-world observations from our honeypot network that help the entire security community understand and defend against this emerging threat."

**Demo Points:**
1. Show the full MITRE matrix with technique coverage
2. Select an attack campaign to see its technique progression
3. Highlight the heatmap showing which techniques are most commonly used

**Key Question Answered:** "What's the complete threat landscape?"

---

## Closing (30 seconds)

> "Project Canary gives you three superpowers against AI agent attacks:
> 1. **Capability measurement** - Know what AI agents can actually do
> 2. **Attribution** - Know who is attacking (human, script, or AI agent)
> 3. **Prediction** - Know what they'll do next and how to stop them
>
> We're turning honeypots from passive decoys into active intelligence platforms."

---

## Technical Architecture (if asked)

```
┌─────────────────────────────────────────────────────────────────┐
│                        Honeypot Websites                        │
│  (Various complexity levels - basic forms to complex workflows) │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Granular Event Capture                       │
│     (clicks, scrolls, timing, navigation, form interactions)     │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Behavioral Analysis Engine                    │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │   Timing     │  │    Click     │  │     Engagement       │   │
│  │  Analysis    │  │   Patterns   │  │      Metrics         │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Classification                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐    │
│  │  Human   │  │  Script  │  │ AI Agent │  │    Model     │    │
│  │ Detection│  │ Detection│  │ Detection│  │ Attribution  │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Red Team Pattern Matching                     │
│         (Compare to known AI agent attack trajectories)          │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                      TTP Prediction Engine                       │
│    ┌─────────────────┐  ┌─────────────────────────────────┐     │
│    │  Predicted TTPs │  │  Recommended Mitigations        │     │
│    │  (MITRE ATT&CK) │  │  (Prioritized by predicted TTPs)│     │
│    └─────────────────┘  └─────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

---

## FAQ Responses

**Q: How do you get ground truth for training?**
> "We run internal red-team AI agents against our own honeypots with full observability. We capture both the agent's internal reasoning and the external events, creating labeled training data."

**Q: What's the accuracy of the classifier?**
> "We're still in early stages, but initial testing shows ~85% accuracy distinguishing AI agents from humans, and ~70% accuracy on model attribution. The classifier improves as we collect more red-team data."

**Q: How does this scale?**
> "The event capture is lightweight JavaScript that can be added to any website. The analysis runs server-side and can process events in real-time or batch mode."

**Q: What models can you detect?**
> "Currently we have fingerprints for GPT-4, Claude, and Llama-based agents. Each has distinct timing patterns based on their inference characteristics."
