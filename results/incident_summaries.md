# Incident summaries (ollama: qwen2.5:3b-instruct)

Facts come from the detector; the model only words them. 'Red-team label' is shown for evaluation and is never given to the model.

## INC-08-011: INC-08-011: 322 logins to 277 hosts by 55 users (C17693, C3435, C18025, C20427, U66, U8777, U162, U3635, U293, U1480)

Source host C17693 made 322 logins to 277 hosts in 10 active hours, mostly as user U66. This is a significant increase from the user's usual activity.

**Why flagged:** One source host reaching many new hosts and one user reaching many new hosts at once, with unusual authentication methods.

**Next steps:**

- Review the login history of U66 on C17693 for signs of automation or unusual behavior
- Check if C17693 was part of a larger attack or if it was compromised
- Examine the network traffic between C17693 and the new hosts to identify any patterns or anomalies

*Source: llm; red-team label 1*

## INC-13-040: INC-13-040: 67 logins to 58 hosts by 8 users (C5400, C17693, C5445, C5356, C21830, C15117), 08:00-16:59

Source hosts C5400, C17693, C5445, C5356, C21830, and C15117 made 67 logins to 58 hosts by 8 users in 5 active hours. 63 of these were first-time logins for both the source host and the destination.

**Why flagged:** One source host reaching many new hosts and one user reaching many new hosts, deviating from normal behavior.

**Next steps:**

- Review process starts on C5400 between 08:00 and 17:00
- Check if U3635 ran a script or admin tool from C5400
- Review later logins from C5400 to rare hosts such as C1028

*Source: llm; red-team label 1*

## INC-14-046: Bulk sweep: C15244 using 3 accounts reached 6746 hosts, day 14 10:00-18:59

Day 14, 10:00-18:59 (6 active hours): 6749 logins to 6746 hosts by 3 users from 1 source host. Source hosts by logins: C15244 (6749). Baseline for source host C15244 (days 1-6): not seen at all. Baseline for user U6836 (days 1-6): not seen at all.

**Why flagged:** Authentication: 100% NTLM. 92% of destinations had been used by at most 2 users before. 33% were followed by a new process or new network flow on the destination. Alert reasons: one source host reaching many new hosts; one user reaching many new hosts.

**Next steps:**

- Ask the owner of U6836 whether they ran a script or admin tool from C15244
- Check process starts on C15244 during 10:00-18:59
- Review logins to rare destinations such as C100, C1000

*Source: template; validator: ungrounded_numbers:9; red-team label 0*

## INC-15-073: INC-15-073: User U636 logged into 101 new hosts (mostly C1495)

User U636 logged into 101 new hosts by 1 source host C1495 in a single hour, all of which were the source host's first login, and all of the user's first login to those hosts.

**Why flagged:** One user reaching many new hosts in a short time, mostly over NTLM, deviates from the baseline.

**Next steps:**

- Review the process starts on C1495 between 22:00 and 00:00
- Check if U636 ran any scripts or admin tools that could have caused this
- Review the network flows and processes on the 101 new hosts

*Source: llm; red-team label 0*

## INC-12-031: INC-12-031 reached 110 new hosts using 23 users (mostly U66), 09:00-18:00

Source host C17693 made 134 logins to 110 hosts by 23 users in 10 hours, 64 of them as U66 and 100% first-time logins. On days 1-6, U66 reached about 1.5 new hosts per active day.

**Why flagged:** One user suddenly reaching many new hosts, mostly over NTLM, matches lateral movement.

**Next steps:**

- Check process starts on C17693 between 09:00 and 19:00
- Review later logins from C17693 to rare hosts such as C102 and C1036
- Ask the owner of U66 whether they ran a script or admin tool from C17693

*Source: llm (retried); red-team label 1*

## INC-12-029: Lateral-movement pattern: C1298 using 2 accounts reached 6 hosts, day 12 14:00-14:59

Day 12, 14:00-14:59 (1 active hour): 9 logins to 6 hosts by 2 users from 1 source host. Source hosts by logins: C1298 (9). Baseline for source host C1298 (days 1-6): active on 6 of 6 days, about 0.3 first-time destinations per active day. Baseline for user U748 (days 1-6): active on 6 of 6 days, about 7.7 first-time destinations per active day.

**Why flagged:** Authentication: 100% NTLM. 0% of destinations had been used by at most 2 users before. 0% were followed by a new process or new network flow on the destination. Alert reasons: one source host reaching many new hosts.

**Next steps:**

- Ask the owner of U748 whether they ran a script or admin tool from C1298
- Check process starts on C1298 during 14:00-14:59
- Review logins to rare destinations such as C1003, C1056

*Source: template; validator: ungrounded_numbers:8; red-team label 0*

## INC-12-036: INC-12-036: Source Host C754 Reached 7 New Hosts (U1723) in 1 Hour

Source host C754 logged in 7 times to 7 different hosts in 1 hour, all by user U1723. This is unusual as U1723 has only logged in to 6 of the 7 hosts before.

**Why flagged:** Source host C754 reached many new hosts in a short time, mostly by U1723, who has only logged in to 6 of the 7 hosts before.

**Next steps:**

- Check if U1723 ran a script or tool that could have accessed these hosts
- Review process starts on C754 between 09:00 and 09:59
- Look for any new network flows or processes on the 7 new hosts

*Source: llm; red-team label 0*

## INC-14-048: INC-14-048: Source Host C22147 Reached 17 New Hosts

Source host C22147 logged in 17 times to 17 different hosts in a single hour, all by user U4335. This is unusual as the source host and user have not logged into these hosts before.

**Why flagged:** A single source host reaching so many new hosts in a short time, especially by a single user, is suspicious.

**Next steps:**

- Review the login history of user U4335 on C22147 for signs of automation or unusual behavior.
- Check if any of the new hosts are known to be compromised or part of a known attack vector.
- Look for any new processes or network flows on the new hosts that were not seen in the baseline.

*Source: llm; red-team label 0*

## INC-08-013: INC-08-013: Source Host C2969 Reached 16 New Hosts (mostly U726)

Source host C2969 logged in 16 times to 16 different hosts in 1 hour, all by user U726. This is unusual as U726 typically logs in to only a few hosts per day.

**Why flagged:** One user suddenly logging into many new hosts, mostly over NTLM, is suspicious for lateral movement.

**Next steps:**

- Review login history of U726 to see if they ran a script or tool from C2969
- Check if any new processes or network flows appeared on the 16 new hosts
- Look for other unusual activity on C2969 around the time of these logins

*Source: llm; red-team label 0*

## INC-07-009: Bulk sweep: C5802 using 3 accounts reached 314 hosts, day 7 01:00-23:59

Day 7, 01:00-23:59 (7 active hours): 316 logins to 314 hosts by 3 users from 8 source hosts. Source hosts by logins: C5802 (112), C5808 (108), C5787 (91), C15701 (1), C23930 (1), C26969 (1), and 2 more. Baseline for source host C5802 (days 1-6): active on 6 of 6 days, about 98.5 first-time destinations per active day. Baseline for user U1718 (days 1-6): active on 6 of 6 days, about 304.2 first-time destinations per active day.

**Why flagged:** Authentication: 100% NTLM. 95% of destinations had been used by at most 2 users before. 15% were followed by a new process or new network flow on the destination. Alert reasons: one source host reaching many new hosts; one user reaching many new hosts.

**Next steps:**

- Ask the owner of U1718 whether they ran a script or admin tool from C5802
- Check process starts on C5802 during 01:00-23:59
- Review logins to rare destinations such as C10014, C10093

*Source: template; validator: ungrounded_numbers:23,52.5,312; red-team label 0*

## INC-15-056: INC-15-056: C10071 reached 1 new host by U4239 (16:00-16:59)

Source host C10071 logged in to a single host by user U4239 in a single hour, with all logins being NTLM-authenticated. This is unusual for C10071, which typically logs in to 6 new hosts per active day.

**Why flagged:** A single user from a single host logging into a new host without prior use, all logins via NTLM, is suspicious.

**Next steps:**

- Check if U4239 ran a script or tool that could have logged in to the new host
- Review process starts on C10071 around 16:00
- Look for other logins from C10071 to hosts that are not in the baseline

*Source: llm; red-team label 0*

## INC-15-057: INC-15-057: C1019 reached 1 new host using U106, 16:00-16:59

Source host C1019 logged in to a single host as user U106, the first login for both. This was unusual as C1019 typically logs in to 6 hosts per day, on average.

**Why flagged:** One user logging in to a single host for the first time, with no prior history of use, is suspicious.

**Next steps:**

- Check if U106 ran any scripts or tools that could have caused this login
- Review the network traffic from C1019 to C5571 during the login window
- Verify if C5571 had any prior use by U106 or any other user

*Source: llm; red-team label 0*

