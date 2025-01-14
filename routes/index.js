const express = require("express")
const router = express.Router()
const {
  signup,
  signupLimiter,
  login,
  loginLimiter,
  verifyJwt,
  sendOtp,
  otpLimiter,
  verifyingOtp,
  resetpassword,
} = require("../controllers/controller")

// Rendering Page
router.get("/", (req, res) => {
  res.render("index")
});

router.get("/signup", (req, res) => {
  res.render("signup")
});

router.get("/forgotpassword", (req, res) => {
  res.render("forgotpassword")
});

router.get("/dashboard", (req, res) => {
  res.render("dashboard")
});

// Route to Create new user.
router.post("/signup", signupLimiter, signup);

// Route to Login
router.post("/login", loginLimiter, login);

//Route to verfyJwt
router.post("/verifyJwt", verifyJwt);

//Router to Send OTP
router.post("/sendOtp", otpLimiter, sendOtp);

//Router to Verify OTP
router.post("/verifyingOtp", verifyingOtp);

//Router to Reset password
router.post("/resetpassword", resetpassword);

module.exports = router;