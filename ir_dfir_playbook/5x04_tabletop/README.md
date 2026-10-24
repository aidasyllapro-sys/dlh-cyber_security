# 5x04 - The Tabletop

> An exercise that never surprises its participants was never testing them.

## Scenario recap

MedDefense Health Systems depends on Nexus Patient Scheduling, a SaaS vendor integrated with Epic
via a certified HL7 FHIR API, for roughly 3,500 weekly patient-facing interactions across three
sites. Nexus is a Business Associate under MedDefense's HIPAA obligations. This module designs and
documents a tabletop exercise around a supply chain compromise scenario: a malicious, validly
signed update pushed through Nexus's automatic update channel, discovered via an outbound traffic
alert on the Main campus scheduling server.

The goal of this module is not to respond to a real incident, but to design an exercise capable of
revealing real organizational gaps before an incident like this one actually happens.

## Grounding materials

- `nexus_vendor_profile.md` - vendor profile for Nexus Patient Scheduling (product, integration
  topology, BAA terms, last security review, facilitator-only notes used only to shape the
  scenario, never copied verbatim into participant-facing documents)

## Task 0 - Understand What Makes a Tabletop Work

A 6-question quiz built around a real-world failure case (Community Health Network, 2025), used to
establish the design principles this module's deliverables must follow: injects over slides,
facilitator neutrality over validation, decision-forcing pressure over clean resolution, and
findings that name a gap, an owner, and a validation method rather than vague recommendations.

## Task 1 - Write the Exercise Scenario

`exercise_scenario.md` - the participant-facing document distributed at the start of the exercise.
Built from `nexus_vendor_profile.md` without exposing any facilitator-only notes. Establishes the
opening situation (three-day-old compromise, 45-minute-old SOC alert), the known facts at exercise
start, two organizational ambiguities with no clean answer, the patient safety dimension (possible
silent modification of appointment records), and the HIPAA Business Associate notification tension.

## Contents

| File | Task | Description |
|---|---|---|
| `exercise_scenario.md` | 1 | Participant-facing tabletop exercise scenario |

*(This table will grow as further tasks in this module are completed.)*
