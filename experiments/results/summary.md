# Experiment results

Each value is the mean of 3 runs, followed by the standard deviation across runs.
Every run used 50 connections and 100 messages.

## TCP connection setup (ms)

| Condition | plain | tls | tls_e2e |
|---|---|---|---|
| No impairment | 0.10 ± 0.02 | 0.16 ± 0.03 | 0.11 ± 0.01 |
| +20 ms RTT | 20.49 ± 0.12 | 20.60 ± 0.07 | 20.50 ± 0.03 |
| +100 ms RTT | 100.79 ± 0.13 | 100.89 ± 0.10 | 100.88 ± 0.09 |
| 2% loss | 61.43 ± 40.80 | 61.34 ± 20.47 | 27.23 ± 23.42 |
| 5% loss | 81.73 ± 20.49 | 135.39 ± 11.78 | 108.82 ± 12.21 |

## TLS 1.3 handshake on top of TCP (ms)

| Condition | plain | tls | tls_e2e |
|---|---|---|---|
| No impairment | 0.00 ± 0.00 | 1.66 ± 0.19 | 1.43 ± 0.07 |
| +20 ms RTT | 0.01 ± 0.00 | 24.38 ± 0.22 | 24.17 ± 0.70 |
| +100 ms RTT | 0.01 ± 0.00 | 106.62 ± 0.45 | 106.18 ± 0.26 |
| 2% loss | 0.00 ± 0.00 | 16.54 ± 4.16 | 11.75 ± 6.67 |
| 5% loss | 0.00 ± 0.00 | 21.17 ± 9.11 | 28.05 ± 11.74 |

## Total time before the first message can be sent (ms)

| Condition | plain | tls | tls_e2e |
|---|---|---|---|
| No impairment | 0.10 ± 0.02 | 1.81 ± 0.22 | 1.54 ± 0.08 |
| +20 ms RTT | 20.50 ± 0.12 | 44.98 ± 0.28 | 44.67 ± 0.72 |
| +100 ms RTT | 100.79 ± 0.13 | 207.51 ± 0.50 | 207.06 ± 0.17 |
| 2% loss | 61.44 ± 40.80 | 77.88 ± 17.19 | 38.98 ± 17.38 |
| 5% loss | 81.73 ± 20.49 | 156.55 ± 8.74 | 136.88 ± 21.85 |

## Message round-trip time through the relay (ms, mean)

| Condition | plain | tls | tls_e2e |
|---|---|---|---|
| No impairment | 0.58 ± 0.03 | 0.74 ± 0.12 | 0.76 ± 0.01 |
| +20 ms RTT | 22.54 ± 0.14 | 23.38 ± 0.19 | 23.42 ± 0.40 |
| +100 ms RTT | 103.64 ± 0.07 | 104.08 ± 0.13 | 104.37 ± 0.22 |
| 2% loss | 8.02 ± 3.37 | 11.41 ± 3.81 | 8.06 ± 3.23 |
| 5% loss | 25.30 ± 2.07 | 21.72 ± 12.87 | 29.07 ± 1.41 |

## Message round-trip time through the relay (ms, median)

| Condition | plain | tls | tls_e2e |
|---|---|---|---|
| No impairment | 0.55 ± 0.03 | 0.70 ± 0.10 | 0.73 ± 0.01 |
| +20 ms RTT | 22.29 ± 0.16 | 23.12 ± 0.21 | 23.16 ± 0.51 |
| +100 ms RTT | 103.58 ± 0.15 | 103.98 ± 0.05 | 104.42 ± 0.26 |
| 2% loss | 1.00 ± 0.30 | 1.22 ± 0.20 | 0.97 ± 0.18 |
| 5% loss | 1.54 ± 0.36 | 1.57 ± 0.71 | 1.78 ± 0.35 |

## Bytes on the wire per message round trip

| Condition | plain | tls | tls_e2e |
|---|---|---|---|
| No impairment | 527.50 ± 0.00 | 571.50 ± 0.00 | 745.50 ± 0.00 |
| +20 ms RTT | 527.50 ± 0.00 | 571.50 ± 0.00 | 745.50 ± 0.00 |
| +100 ms RTT | 527.50 ± 0.00 | 571.73 ± 0.40 | 745.50 ± 0.00 |
| 2% loss | 543.37 ± 4.91 | 591.73 ± 5.57 | 767.17 ± 13.23 |
| 5% loss | 568.26 ± 5.54 | 611.61 ± 23.35 | 823.22 ± 5.15 |
