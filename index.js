const express = require("express");
const app = express();
const PORT = 8000;
const bodyParser = require("body-parser");
const cookieParser = require('cookie-parser');
const nodemailer = require("nodemailer");
const User = require("./MODELS/UserSchema");
const errorHandler = require("./MIDDLEWARE/ErrMiddleware");
const authTokenHandler = require("./MIDDLEWARE/CheckAuthToken");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
require("dotenv").config();
require("./db");

app.use(bodyParser.json());
app.use(cors());
app.use(cookieParser());

app.get("/", (req, res) => {
  res.json({ message: "The API is working" });
});

//method to create a response
function createResponse(ok, message, data) {
  return {
    ok,
    message,
    data,
  };
}

//method to create transport for using nodemailer
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.COMPANY_EMAIL_ID,
    pass: process.env.COMPANY_EMAIL_PASSWORD,
  },
});

//register API
app.post("/register", async (req, res, next) => {
  try {
    const { name, email, password } = req.body;
    const existingUser = await User.findOne({ email: email });

    if (existingUser) {
      return res
        .status(409)
        .json(createResponse(false, "Email already exists"));
    }

    const newUser = new User({
      name,
      password,
      email,
    });

    await newUser.save(); // Await the save operation

    res.status(201).json(createResponse(true, "User registered successfully"));
  } catch (err) {
    // Pass the error to the error middleware
    next(err);
  }
});

//login API
app.post("/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      //check if email exists ?
      return res.status(400).json(createResponse(false, "Email not found"));
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      //check if password matches
      return res.status(400).json(createResponse(false, "Invalid credentials"));
    }

    // Generate an authentication token with a 10-minute expiration
    const authToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "10m" }
    );

    // Generate a refresh token with a 1-day expiration
    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_REFRESH_SECRET_KEY,
      { expiresIn: "1d" }
    );
    res.cookie("authToken", authToken, { httpOnly: true });
    res.cookie("refreshToken", refreshToken, { httpOnly: true });
    res.status(200).json(
      createResponse(true, "Login successful", {
        authToken,
        refreshToken,
      })
    );
  } catch (err) {
    next(err);
  }
});

//check if already logged in
app.get("/checklogin", authTokenHandler, async (req, res) => {
  res.json({
    ok: true,
    message: "User authenticated successfully",
  });
});

// API for sending otp
app.get("/sendotp", (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000);
  try {
    const mailOptions = {
      from: process.env.COMPANY_EMAIL_ID,
      to: email,
      subject: "Your OTP Verification Code",
      text: ` Hello dear

      This is an automated generated response ! To ensure the security of your account, please use the following OTP mentioned below :

      OTP Code: ${otp}
      
      Please enter this OTP code in the designated field on our website or app to verify your email address.
      
      Please note that this OTP is valid for the next 5 minutes.
      
      Thank you for visting us. We look forward to serving you.
      
      Sincerely,
      
      Avinash .`,
    };
    transporter.sendMail(mailOptions, async (err, info) => {
      if (err) {
        console.log(err);
        res.status(500).json({
          message: err.message,
        });
      } else {
        res.json({
          message: "OTP sent successfully",
          otp: otp,
        });
      }
    });
  } catch (error) {
    next(err);
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

app.use(errorHandler);
