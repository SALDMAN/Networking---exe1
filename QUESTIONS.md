# Evaluation questions (assignment item 33)

Capture used: `pcap-files/hasnafa (1).pcapng` (the httpbin.org capture: GET /forms/post, then POST /post).

The expected answers were found by searching the raw packet bytes, not with the HTTP extractor, so the
check does not depend on the code under test. Please confirm them against your Part B Wireshark answers.

| # | Question (typed in the dashboard) | What it tests | Expected answer | Evidence frames |
|---|---|---|---|---|
| 1 | Which HTTP request was the slowest, and how long did it take? | Slowest request (item 31) | `GET httpbin.org/forms/post`, about 157 ms (156.6 ms) | 2530, 2578 |
| 2 | How many requests were sent to httpbin.org? | Count per Host (item 31) | 2 (GET /forms/post and POST /post) | 2530, 4788 |
| 3 | Which status codes were returned? | Status Codes (item 31) | Only `200` (both responses `200 OK`) | 2578, 4900 |
| 4 | What happened in the POST request? | What happened in a transaction (item 31) | `POST httpbin.org/post`, answered `200 OK` after about 152 ms (IP addresses and ports are not required) | 4788, 4900 |
| 5 | What are the Content-Type and Content-Length of the response to GET /forms/post? | Header details | `text/html; charset=utf-8`, 1397 | 2578 |

## How a result is judged

- **Pass:** the answer contains the expected facts (numbers within rounding) and cites the expected frames.
- **Fail:** a wrong or missing fact, or a cited frame that is not in the capture.
- Item 34 (one documented AI mistake) is filled in below only if a real failure shows up.

## Item 34: a case where the AI got it wrong, and the fix

**Question 5** ("What are the Content-Type and Content-Length of the response to GET /forms/post?") failed on
the first run (2026-11-16 14:12, `gemini-2.5-flash`, 4 of 5 passed).

- **What the AI said:** "Content-Type: text/html; charset=utf-8. Content-Length is not available in the
  provided data." The capture shows `content-length: 1397` in frame 2578, so the answer was incomplete.
- **Why:** the fault was in our system, not the model's reasoning. `QuestionAgent._row` sent the model only
  `content_type` for each transaction, so `content-length` never reached it. The model reported honestly that it
  did not have the value instead of inventing one, which is the behavior our system prompt asks for.
- **Fix:** `QuestionAgent._row` (`netdash/agent.py`) now sends the full `request_headers` and
  `response_headers` of each transaction (test: `test_prompt_includes_request_and_response_headers`). The
  token cost is higher, but `LLM_MAX_TRANSACTIONS` in `.env` still caps it.
- **Lesson:** when an AI answer says "not available", check what data it was actually given before blaming the
  model.

## Results

Run 2026-11-16 14:34 with `@cf/google/gemma-4-26b-a4b-it` on `hasnafa (1).pcapng` (`python evaluate.py`).

| # | AI answer | Cited frames | Result |
|---|---|---|---|
| 1 | GET httpbin.org/forms/post was the slowest request, taking 156.6 ms. | 2530, 2578 | PASS |
| 2 | 2 | 2530, 4788 | PASS |
| 3 | 200 | 2578, 4900 | PASS |
| 4 | A POST request was made to httpbin.org/post from 10.12.20.32:60071 to 3.221.253.123:80, which returned a status code of 200 with a response time of 152.0 ms. | 4788, 4900 | PASS |
| 5 | The Content-Type is text/html; charset=utf-8 and the Content-Length is 1397. | 2578 | PASS |
