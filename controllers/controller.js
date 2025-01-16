const db = require("../config/db")
const jwt = require("jsonwebtoken")
const nodemailer = require("nodemailer")
const crypto = require("crypto") 
const rateLimit = require("express-rate-limit")
const { body, validationResult } = require("express-validator")

//limiting configuration
const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: "Too many attempt tried, please try again after 15 minutes",
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: "Too many login attempts, please try again after 15 minutes",
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3,
  message: "Too many OTP requests, please try again after 15 minutes",
});

//Signup
const signup = [
  body("name").notEmpty().withMessage("Name is required"),
  body("email").isEmail().withMessage("Invalid email address"),
  body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters"),
  body("confirmpassword").custom((value, { req }) => value === req.body.password).withMessage("Passwords do not match"),

  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() })
    }

    const { name, email, password } = req.body;

    try {
      const checkQuery = "SELECT * FROM users WHERE email = ?";
      db.query(checkQuery, [email], async (err, results) => {
        if (err) {
          console.error("Error checking user existence:", err)
          return res.status(500).send("An internal server error occurred")
        }

        if (results.length > 0) {
          return res.redirect("/")
        }

        const salt = crypto.randomBytes(16).toString("hex")
                                
        //Hashing the password with the salt using SHA-256
        const hashedPassword = crypto.createHmac("sha256", salt).update(password).digest("hex");

        const insertQuery =
          "INSERT INTO users (name, email, password, salt) VALUES (?, ?, ?, ?)";
        db.query(
          insertQuery,
          [name, email, hashedPassword, salt],
          (err, result) => {
            if (err) {
              console.error("Error inserting data:", err)
              return res.status(500).send("Error saving data to database")
            }

            // Generate JWT
            const token = jwt.sign({ email }, process.env.SECRET_KEY, {
              expiresIn: "10d",
            })
             res.cookie("jwt", token, {
              maxAge: 10 * 24 * 60 * 1000, // 10Days
              httpOnly: true,
            });

            res.redirect("/dashboard")
          }
        );
      });
    } catch (error) {
      console.error("Error during signup:", error)
      res.status(500).send("An internal server error occurred")
    }
  },
];

//Login
const login = [
  body("email").isEmail().withMessage("Invalid email address"),
  body("password").isLength({ min: 6 }).withMessage("Password is Too Short"),

  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() })
    }

    const { email, password } = req.body;

    try {
      const checkQuery = "SELECT * FROM users WHERE email = ?";
      db.query(checkQuery, [email], async (err, results) => {
        if (err) {
          console.error("Error checking user:", err)
          return res.status(500).send("An internal server error occurred")
        }

        if (results.length === 0) {
          return res.status(400).redirect("/signup")
        }

        const user = results[0];
        const { password: storedPassword, salt } = user;

        const hashedPassword = crypto
          .createHmac("sha256", salt)
          .update(password)
          .digest("hex");

        if (hashedPassword !== storedPassword) {
          return res.status(400).send({ error: "Invalid credentials" })
        }

        // Generate JWT
        const token = jwt.sign({ email }, process.env.SECRET_KEY, {
          expiresIn: "10d",
        });

        res.cookie("jwt", token, {
          maxAge: 10 * 24 * 60 * 1000, // 10Days 
          httpOnly: true,
        });
        res.redirect("/dashboard");
      });
    } catch (error) {
      console.error("Error during login:", error)
      res.status(500).send("An internal server error occurred")
    }
  },
];

//Verify JWT
const verifyJwt = async (req, res) => {
  const { token } = req.body;

  try {
    if (!token) {
      return res.status(401).json({
        success: false,
        error: "JWT token not provided",
      });
    }

    const decoded = jwt.verify(token, process.env.SECRET_KEY)

    db.query(
      "SELECT * FROM users WHERE email = ?",
      [decoded.email],
      (err, result) => {
        if (err) {
          console.error("Database error:", err.message)
          return res.status(500).json({
            success: false,
            error: "Database error",
          });
        }

        const user = result[0];
        if (user) {
          return res.json({
            success: true,
            redirect: "/dashboard",
          });
        } else {
          return res.json({
            success: false,
            error: "User not found",
          });
        }
      }
    );
  } catch (error) {
    console.error("Error verifying JWT token:", error.message)
    return res.status(401).json({
      success: false,
      error: error.message,
    });
  }
};

// Generate OTP
const generateOtp = () => {
  return Math.floor(100000 + Math.random() * 900000).toString()
};

// Forgot Password
const sendOtp = [
  otpLimiter,
  async (req, res) => {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" })
    }

    const otp = generateOtp();

    const transporter = nodemailer.createTransport({
      service: "gmail",
      port: 465,
      secure: true, 
      logger: true,
      debug: true,
      secureconnection: false,
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
      tls: {
        rejectUnauthorized: true,
      },
    });

    const mailOption = {
      from: '"ABC-BANK" <ABC-bank@gmail.com>',
      to: email,
      subject: "Your OTP for Password Reset",
      text: `Your OTP for password reset is ${otp}. It is valid for 10 minutes.`,
      html: `<p>Your OTP for password reset is <b>${otp}</b>. It is valid for 10 minutes.</p>`,
    };

    try {
      await transporter.sendMail(mailOption);
      // console.log(`OTP sent to ${email}: ${otp}`);

      const query = `
        INSERT INTO resetotp (email, otp)
        VALUES (?, ?)
        ON DUPLICATE KEY UPDATE otp = VALUES(otp);
      `;

      db.query(query, [email, otp], (err) => {
        if (err) {
          console.error("Database error while storing OTP:", err);
          return res.status(500).json({ message: "Failed to store OTP", error: err });
        }
        res.status(200).json({ response: "OTP sent successfully" });
      });
    } catch (error) {
      console.error("Error Sending OTP:", error)
      res.status(500).json({ message: "Failed to send OTP", error })
    }
  },
];

// Verifying OTP
const verifyingOtp = async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ message: "Email and OTP are required" })
  }

  const query = `SELECT otp FROM resetotp WHERE email = ?`;
  db.query(query, [email], (err, results) => {
    if (err) {
      console.error("Database error while verifying OTP:", err)
      return res
        .status(500)
        .json({ message: "Failed to verify OTP", error: err })
    }

    const clientOtp = String(otp).trim()
    const dbOtp = String(results[0].otp).trim()

    if (clientOtp === dbOtp) {
      return res.status(200).json({
        message: "OTP Verified Successfully",
        redirect: "/dashboard",
      });
    } else {
      return res.status(400).json({ message: "Invalid OTP" })
    }
  });
};

// Reset Password
const resetpassword = async (req, res) => {
  const { newpassword, email } = req.body;

  if (!newpassword || !email) {
    return res
      .status(400)
      .json({ success: false, message: "Email and password are required." })
  }

  try {
    // Fetch the current password and salt from the database
    const getUserQuery = `SELECT password, salt FROM users WHERE email = ?`;
    db.query(getUserQuery, [email], (err, results) => {
      if (err) {
        console.error("Database error while fetching user:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error.", error: err })
      }

      if (results.length === 0) {
        return res
          .status(404)
          .json({ success: false, message: "User not found." });
      }

      const { password: currentHashedPassword, salt: currentSalt } = results[0];

      // Hash the new password with the current salt
      const hashedNewPassword = crypto
        .createHmac("sha256", currentSalt)
        .update(newpassword)
        .digest("hex");

      if (hashedNewPassword === currentHashedPassword) {
        return res.status(400).json({
          success: false,
          message: "New password cannot be the same as the current password.",
        });
      }

      const newSalt = crypto.randomBytes(16).toString("hex")

      const newHashedPassword = crypto
        .createHmac("sha256", newSalt)
        .update(newpassword)
        .digest("hex");

      const updateQuery = `UPDATE users SET password = ?, salt = ? WHERE email = ?`;
      db.query(
        updateQuery,
        [newHashedPassword, newSalt, email],
        (err, updateResults) => {
          if (err) {
            console.error("Database error while updating password:", err)
            return res.status(500).json({
              success: false,
              message: "Failed to update password.",
              error: err,
            });
          }

          if (updateResults.affectedRows === 0) {
            return res
              .status(404)
              .json({ success: false, message: "User not found." })
          }

          const token = jwt.sign({ email }, process.env.SECRET_KEY, {
            expiresIn: "10d",
          });

          res.cookie("jwt", token, {
            maxAge: 10 * 24 * 60 * 1000,
            httpOnly: true,
          });
          res.json({
            success: true,
            message: "Password updated successfully.",
            redirect: "/dashboard",
          });
        }
      );
    });
  } catch (error) {
    console.error("Error during password reset:", error);
    res
      .status(500)
      .json({ success: false, message: "An internal server error occurred." })
  }
};

module.exports = {
  signup,
  login,
  verifyJwt,
  sendOtp,
  verifyingOtp,
  resetpassword,
  otpLimiter,
  loginLimiter,
  signupLimiter,
};
