// index.ts
import express from 'express';
import session from 'express-session';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import bcrypt from 'bcrypt';
import { sendVerificationEmail, sendResetPasswordEmail } from './email.service';
import { generateToken, generateOTP, verifyOTP } from './token.service';

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(session({ secret: 'your-secret-key', resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

const users: User[] = [];

// User Model
interface User {
  id: string;
  username: string;
  password: string;
  email: string;
  verified: boolean;
  verificationToken: string;
  resetToken: string;
  resetTokenExpiration: Date;
  otpSecret: string;
  // Add other user properties as needed
}

// Passport Configuration
passport.use(
  new LocalStrategy(async (username, password, done) => {
    const user = users.find((u) => u.username === username);

    if (!user) {
      return done(null, false, { message: 'Incorrect username.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return done(null, false, { message: 'Incorrect password.' });
    }

    return done(null, user);
  })
);

passport.use(
  new GoogleStrategy(
    {
      clientID: 'your-google-client-id',
      clientSecret: 'your-google-client-secret',
      callbackURL: 'http://localhost:3000/auth/google/callback',
    },
    (accessToken, refreshToken, profile, done) => {
      // Implement your own logic for Google authentication
      // ...

      return done(null, user);
    }
  )
);

passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

passport.deserializeUser((id: any, done) => {
  const user = users.find((u) => u.id === id);
  done(null, user);
});

// Email Service
const sendEmail = async (to: string, subject: string, text: string) => {
  // Implement your email service or use nodemailer
  // ...
};

// Routes

// Register Route
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;

  // Check if the username or email is already taken
  if (users.some((u) => u.username === username || u.email === email)) {
    return res.status(400).json({ message: 'Username or email already exists.' });
  }

  // Generate a unique verification token
  const verificationToken = generateToken();

  // Generate OTP secret
  const { secret: otpSecret } = generateOTP();

  // Save the user to the in-memory database
  const user: User = {
    id: generateToken(),
    username,
    password: await bcrypt.hash(password, 10),
    email,
    verified: false,
    verificationToken,
    resetToken: '',
    resetTokenExpiration: new Date(),
    otpSecret,
  };
  users.push(user);

  // Send a verification email
  const verificationLink = `http://localhost:3000/verify-email?token=${verificationToken}`;
  const emailText = `Click on the link to verify your email: ${verificationLink}`;
  await sendEmail(email, 'Email Verification', emailText);

  res.json({ message: 'Registration successful. Check your email for verification.' });
});

// Verification Route
app.get('/verify-email', async (req, res) => {
  const { token } = req.query;
  const user = users.find((u) => u.verificationToken === token);

  if (!user) {
    return res.status(400).json({ message: 'Invalid verification token.' });
  }

  // Verify the token against the database
  user.verified = true;
  // ...

  res.redirect('/login'); // Redirect to the login page
});

// Forgot Password Route
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = users.find((u) => u.email === email);

  if (!user) {
    return res.status(400).json({ message: 'User with this email does not exist.' });
  }

  // Generate a unique reset token and set expiration time
  const resetToken = generateToken();
  const resetTokenExpiration = new Date();
  resetTokenExpiration.setHours(resetTokenExpiration.getHours() + 1);

  // Save the resetToken and resetTokenExpiration to the user in the database
  user.resetToken = resetToken;
  user.resetTokenExpiration = resetTokenExpiration;
  // ...

  // Send a password reset email
  const resetLink = `http://localhost:3000/reset-password?token=${resetToken}`;
  const emailText = `Click on the link to reset your password: ${resetLink}`;
  await sendResetPasswordEmail(email, 'Password Reset', emailText);

  res.json({ message: 'Password reset email sent. Check your email for instructions.' });
});

// Reset Password Route
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  const user = users.find((u) => u.resetToken === token && u.resetTokenExpiration > new Date());

  if (!user) {
    return res.status(400).json({ message: 'Invalid or expired reset token.' });
  }

  // Update the user's password to the new password
  user.password = await bcrypt.hash(newPassword, 10);
  // ...

  res.json({ message: 'Password reset successful.' });
});

// Login Route
app.post('/login', passport.authenticate('local'), (req, res) => {
  res.json({ message: 'Login successful', user: req.user });
});

// Google Authentication Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  res.redirect('/');
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
