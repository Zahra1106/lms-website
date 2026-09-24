# Ilmora LMS: Learning Management System

A full-stack Learning Management System for managing courses, students and assessments.
Students enroll, study lessons, take quizzes and submit assignments. Instructors build courses and grade work. Admins manage users.

**Live demo:** _add your Vercel URL here_

---

## Task workflow and where it is implemented

| Step | Requirement | Implementation |
|---|---|---|
| 1 | Design course and student modules | Course, lesson, quiz, assignment, enrollment, progress and user tables (`server/app.js`, `SCHEMA`) |
| 2 | Authentication and authorization | bcrypt passwords, httpOnly cookie sessions, three roles (student, instructor, admin), role checks on every route, optional 2FA |
| 3 | Course management | Instructors create, edit and delete courses, lessons, quiz questions and assignments. Admins can manage every course |
| 4 | Quizzes, assignments, progress tracking | Server-graded quizzes, assignment submission with score and feedback, per-lesson progress bars, certificate at 100% |
| 5 | Deploy and optimize | Vercel + Turso deployment, Vite production build, compressed 1.2 MB background video, security headers |

## Key features

- **Course management:** create, edit, delete courses. Add lessons (with optional material links), quiz questions and assignments with due dates. Search courses.
- **Student dashboard:** enrolled courses, average progress, quiz average, graded assignments.
- **Assignments and quizzes:** multiple-choice quizzes graded on the server (students never receive the correct answers). Assignment submissions are graded 0 to 100 with written feedback.
- **Progress tracking:** students mark lessons done and see progress per course. Instructors see every enrolled student and their progress.
- **Roles:** students study, instructors teach, admins manage users, approve instructors and reset passwords.
- **Scroll-driven 3D landing page:** background video scrubs with the scroll, glassmorphism panels and tilt effects.

## Skills covered

Advanced full-stack development, authentication and security, system architecture, real-world application development.

## Roles and permissions

| Action | Student | Instructor | Admin |
|---|---|---|---|
| Browse and enroll in courses | yes | no | no |
| Mark lessons, take quizzes, submit assignments | yes (enrolled) | no | no |
| Create courses | no | yes | yes |
| Edit or delete a course | no | own courses | all |
| Grade submissions | no | own courses | all |
| Approve instructors, change roles, remove users, reset passwords | no | no | yes |

Instructor sign-ups start as students and need admin approval.

## Tech stack

- Frontend: Vite, vanilla JavaScript, CSS (glassmorphism, 3D transforms)
- Backend: Node.js, Express
- Database: libSQL. A local file (`lms.db`) in development, Turso (hosted SQLite) in production
- Security: bcryptjs, helmet, TOTP two-factor (built on Node `crypto`)
- Hosting: Vercel (static frontend + one serverless function)

## Project structure

```
api/index.js        Vercel serverless entry
server/app.js       Express app: routes, auth, security, database
server/index.js     Local server entry
server/seed.js      Demo courses
src/main.js         Frontend logic
src/style.css       Styles
public/video.mp4    Scroll background video
vercel.json         Routing and security headers
```

## API overview

| Area | Endpoints |
|---|---|
| Account | `POST /api/signup`, `/login`, `/logout`, `/password`, `/2fa/setup`, `/2fa/enable`, `/2fa/disable` |
| Data | `GET /api/state` (returns only what the signed-in role may see), `GET /api/public` |
| Courses | `POST /api/courses`, `PUT` and `DELETE /api/courses/:id` |
| Students | `POST /api/courses/:id/enroll`, `/lessons/:i/toggle`, `/quiz`, `/submit` |
| Grading | `POST /api/subs/:id/grade` |
| Admin | `PATCH` and `DELETE /api/users/:id`, `POST /api/users/:id/approve`, `/reset` |

## Run locally

```bash
npm install
npm run dev
```

Open http://localhost:5173. Needs Node 20 or newer. No configuration is needed locally.

Demo accounts created on first start (password `demo1234`):

| Role | Email |
|---|---|
| Admin | admin@ilmora.pk |
| Instructor | sara@ilmora.pk |
| Student | ali@ilmora.pk |

Data is stored in `lms.db`. Delete the file to reset.

## Admin login (production)

Set these environment variables on the hosting platform (Vercel: Project Settings, Environment Variables). On first start with an empty database the app creates this admin account.

```dotenv
ADMIN_EMAIL=admin123@gmail.com
ADMIN_PASSWORD=Kx7#mQ2vLp9$Wt4nRz8!
```

Notes:
- The admin is created only once. Changing `ADMIN_PASSWORD` later does not change an existing admin. Change it from the Account tab instead.
- Anyone who can read this file can sign in as admin on a site that uses these values. Change the password from the Account tab before using the site with real data.

## Deploy on Vercel

1. Push this folder to GitHub. Do not commit `.env` or `*.db`.
2. Create a Turso database at turso.tech. Copy its URL and an auth token.
3. In Vercel choose Add New Project and import the repository. The Vite framework is detected automatically.
4. Add these environment variables:

```dotenv
JWT_SECRET=<long random string>
TURSO_DATABASE_URL=libsql://<your-database>.turso.io
TURSO_AUTH_TOKEN=<token from Turso>
SEED=0
ADMIN_EMAIL=admin123@gmail.com
ADMIN_PASSWORD=Kx7#mQ2vLp9$Wt4nRz8!
```

Generate `JWT_SECRET` with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

5. Deploy. Vercel serves the frontend as static files and runs `api/index.js` as the API.

`JWT_SECRET` encrypts the two-factor secrets, so do not change it after users enable 2FA.

## Security

- Passwords hashed with bcrypt. Sessions are random IDs in an httpOnly, SameSite cookie (Secure in production), stored hashed, valid for 24 hours and revoked on sign-out, password change or admin reset.
- Every route checks the role on the server. Quiz answers are never sent to students.
- Rate limits on every endpoint, stored in the database. Five wrong passwords lock an account for 15 minutes.
- CSRF protection through a required custom header on all non-GET requests.
- Helmet, Content-Security-Policy and HSTS.
- Optional two-factor authentication with an authenticator app.
- Parameterized SQL queries and escaped output.

## Optimization

- Vite production build (minified and hashed assets).
- Background video re-encoded to 1.2 MB with all keyframes for smooth scrolling.
- Static frontend served from the Vercel CDN.

## Limitations and future work

- Email verification and email-based password reset (admins reset passwords instead).
- File uploads for assignments and video hosting for lessons (lessons can link to external material).
- Quiz timer, quiz question types other than multiple choice.
- The Content-Security-Policy allows inline event handlers because the UI uses `onclick` attributes.
- No independent security audit.