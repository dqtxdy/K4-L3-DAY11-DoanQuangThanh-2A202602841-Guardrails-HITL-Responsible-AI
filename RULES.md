# Quy định Lab — Day 11 (RULES)

> Đọc cùng [`README.md`](README.md), [`SUBMISSION.md`](SUBMISSION.md), [`RUBRIC.md`](RUBRIC.md).  
> Bài này là bài **cá nhân** (1 MSSV / 1 repo / 1 link nộp).

---

## 1. Hình thức & nộp bài

- **Cá nhân:** mỗi học viên tự fork/clone starter, đổi tên repo theo quy ước Khóa 4, tự nộp **link repo cá nhân** lên LMS / CodeLabs.
- Dù lớp có thảo luận chung, **không** nộp chung một repo cho nhiều MSSV.
- Tên repo: `K4-L3-DAY11-<HoVaTen>-<MSSV>-Guardrails-HITL-Responsible-AI`  
  Ví dụ: `K4-L3-DAY11-NguyenVanA-2A2026xxxxx-Guardrails-HITL-Responsible-AI`

Chi tiết: [`SUBMISSION.md`](SUBMISSION.md).

---

## 2. Deadline

- **Mặc định:** **23h59 cùng ngày làm Lab** (ICT / GMT+7).
- Nếu Key Coach thông báo gia hạn **trong vòng 48 giờ sau Lab**, hạn mới theo thông báo đó.
- Sau hạn (hoặc hết gia hạn): nộp muộn bị **trừ điểm** theo quy định khóa; commit sửa sau hạn có thể không được tính.

---

## 3. Dùng AI hỗ trợ code

- Được dùng AI (Cursor, ChatGPT, Copilot, …) để **hỗ trợ** viết/debug code.
- Bạn phải **hiểu** và **giải thích** được phần mình nộp khi Key Coach hỏi.
- Không nộp nguyên bài do AI sinh mà bạn không chỉnh / không chạy được.
- Prompt tấn công (red-team) phải do bạn thiết kế có chủ đích — không copy nguyên bộ prompt mẫu của bạn khác.

---

## 4. Sao chép / gian lận

- Không copy code / `outputs/*.json` của bạn khác.
- Không chia sẻ API key, không đẩy secret lên repo công khai.
- Hai bài nộp giống nhau bất thường có thể bị coi là gian lận theo quy định khóa.

---

## 5. API key & dữ liệu nhạy cảm

- Giữ API key trong file `.env` **local** — **không commit** `.env`.
- Chỉ commit `.env.example` (không có key thật).
- Secret trong lab (`admin123`, `sk-vinbank-secret-2024`, …) là **DEMO** — không phải secret thật của ngân hàng; vẫn phải bảo vệ trên **Blue** và **Red Advance** đúng yêu cầu bài.
- Không dán API key vào README, chat công khai, issue, hay commit message.

---

## 6. Artifact & chỉnh sửa sau hạn

- Artifact chấm: file trong `outputs/` do lệnh lab sinh ra — **không** tự tạo placeholder JSON bằng tay.
- **Không** viết `report/*.md` tay — chạy `scripts/grade.py` để **tự sinh** `grade_report.json` + `lab_report.md`.
- Sửa bài sau deadline: chỉ được tính nếu còn trong cửa sổ gia hạn Key Coach đã công bố.

---

## 7. Bonus lab

- Bonus trong [`RUBRIC.md`](RUBRIC.md) là **điểm cộng cho bài lab** (chọn B1 tối đa +5 (chỉ leak Red replay bằng model khó) hoặc B2 tối đa +10), **không** phải điểm giơ tay / phát biểu / pitching trên lớp.
