import { User } from '../models/user.models.js';
import bcryptjs from 'bcryptjs'; // Fixed typo here
import { generateTokenAndSetCookie } from '../utils/generateTokenAndSetCookie.js';
import { sendVerificationEmail, sendWelcomeEmail } from '../mailtrap/emails.js';

// Signup
export const signup = async (req, res) => {
  const { email, password, name } = req.body;

  try {
    // Check for missing fields
    if (!email || !password || !name) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    // Check if user already exists
    const userAlreadyExists = await User.findOne({ email });
    if (userAlreadyExists) {
      return res.status(400).json({ success: false, message: "User already exists" });
    }

    // Hash the password
    const hashedPassword = await bcryptjs.hash(password, 10);

    // Generate verification token and create user
    const verificationToken = Math.floor(100000 + Math.random() * 900000).toString();
    const user = new User({
      email,
      password: hashedPassword,
      name,
      verificationToken,
      verificationTokenExpiresAt: Date.now() + 24 * 60 * 60 * 1000, // Fixed typo here
    });

    // Save user to the database
    await user.save();

    await sendVerificationEmail(user.email, verificationToken)

    // Generate JWT and set it as a cookie
    generateTokenAndSetCookie(res, user._id);

    // Send response excluding password
    res.status(201).json({
      success: true,
      message: "User created successfully",
      user: {
        ...user._doc,
        password: undefined, // Do not send the password back
      },
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

export const verifyEmail = async (req, res) => {
  const { code } = req.body;
  try {
    const user = await User.findOne({
      verificationToken: code,
      verificationTokenExpiresAt: { $gt: Date.now() }
    })

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired verification code"
      })
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpiresAt = undefined;

    await user.save();

    await sendWelcomeEmail(user.email, user.name)
    res.status(200).json({
      success: true,
      message: "Email verified successfully",
      user: {
        ...user._doc,
        password: undefined
      }
    })
  } catch (error) {
    console.log("error in ", error);
    res.status(500).json({
      success: false,
      message: "server error:", error
    })
  }
}

// Login
export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email })
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials"
      })
    }

    const isPasswordValid = await bcryptjs.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials"
      })
    }

    generateTokenAndSetCookie(res, user._id)
    user.lastLogin = Date.now();
    await user.save();

    res.status(200).json({
      success: true,
      message: "Logged in Successfully",
      user: {
        ...user._doc,
        password: undefined
      }
    })
  } catch (error) {
    console.log("Error in login", error);
    return res.status(400).json({
      success: false,
      message: error.message
    })
  }
};

// Logout
export const logout = async (req, res) => {
  res.clearCookie("token");
  res.status(200).json({
    success: true,
    message: "Logged out successfully"
  })
};
