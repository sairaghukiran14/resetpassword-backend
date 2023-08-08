const express = require("express");
const userdb = require("../models/userSchema");
const router = new express.Router();
const bcrypt = require("bcryptjs");
const authenticate = require("../middleware/authenticate");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config();
const JWT_SECRET = process.env.JWTSECRET;

//email config
let transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL, // generated ethereal user
    pass: process.env.PASSWORD, // generated ethereal password
  },
});

//for user registration
router.post("/register", async (req, res) => {
  if (
    !req.body.name ||
    !req.body.email ||
    !req.body.password ||
    !req.body.cpassword
  ) {
    res.status(400).json({ error: "fill all the details" });
  }
  try {
    const preuser = await userdb.findOne({ email: req.body.email });
    if (preuser) {
      res.status(400).json({ error: "user already exists!!" });
    } else if (req.body.password !== req.body.cpassword) {
      res
        .status(400)
        .json({ error: "password and confirm password does not match" });
    }
    // else if(!req.body.email){
    //     res.status(400).json({error:"Invalid Email"});
    // }
    else {
      let newuser = await new userdb({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        cpassword: req.body.cpassword,
      });
      //password hashing
      const storeddata = await newuser.save();
      res.status(200).json({ status: 200, storeddata });
    }
  } catch (error) {
    res.status(422).send(error);
  }
});

//user login

router.post("/login", async (req, res) => {
  if (!req.body.email || !req.body.password) {
    res.status(400).json({ error: "fill all the details" });
  }
  try {
    const uservalid = await userdb.findOne({ email: req.body.email });
    if (uservalid) {
      const ismatch = await bcrypt.compare(
        req.body.password,
        uservalid.password
      );
      if (!ismatch) {
        res.status(400).json({ error: "invalid details" });
      } else {
        const token = await uservalid.generateAuthtoken();
        // console.log(token)
        res.cookie("usercookie", token, {
          expires: new Date(Date.now() + 9 * 60 * 60 * 1000),
          httpOnly: true,
        });
        const result = { uservalid, token };
        res.status(200).json({ status: 200, result });
      }
    } else {
      res.status(401).json({ error: "User does not exist!!!" });
    }
  } catch (error) {}
});

//valid user
router.get("/validuser", authenticate, async (req, res) => {
  try {
    const validuserone = await userdb.findOne({ _id: req.userId });
    res.status(200).json({ status: 200, validuserone });
  } catch (error) {
    res.status(401).json({ status: 401, error });
  }
});

//user logout
router.get("/logout", authenticate, async (req, res) => {
  try {
    req.rootUser.tokens = req.rootUser.tokens.filter((e) => {
      return e.token !== req.token;
    });
    // res.clearCookie(usercookie,{path:"/"});
    req.rootUser.save();
    res.status(200).json({ status: 200 });
  } catch (error) {
    res.status(401).json({ status: 401, error });
  }
});

//send link for reset password
router.post("/sendpasswordlink", async (req, res) => {
  if (!req.body.email) {
    res.status(401).json({ status: 401, message: "Enter Your Email" });
  }
  try {
    const finduser = await userdb.findOne({ email: req.body.email });
    //token generate for reset password

    const token = jwt.sign({ _id: finduser._id }, JWT_SECRET, {
      expiresIn: "120s",
    });
    const setusertoken = await userdb.findByIdAndUpdate(
      finduser._id,
      {
        verifytoken: token,
      },
      { new: true }
    );
    if (setusertoken) {
      const mailOptions = {
        from: "dharani94667@gmail.com", // sender address
        to: req.body.email, // list of receivers
        subject: "Password Reset Link", // Subject line
        text: `This link is valid for 2 minutes https://resetpassword-frontend.vercel.app/forgotpassword/${finduser._id}/${setusertoken.verifytoken}`,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          res.status(401).json({ status: 401, message: "Email not sent" });
        } else {
          res
            .status(200)
            .json({ status: 200, message: "Email sent successfully!!" });
        }
      });
    }
  } catch (error) {
    res.status(401).json({ status: 401, message: "Invalid user" });
  }
});

//verify user for forgot password
router.get("/forgotpassword/:id/:token", async (req, res) => {
  const id = req.params.id;
  const token = req.params.token;
  try {
    const validuser = await userdb.findOne({ _id: id, verifytoken: token });
    const verifyToken = jwt.verify(token, JWT_SECRET);
    if (validuser && verifyToken._id) {
      res.status(200).json({ status: 200, validuser });
    } else {
      res.status(401).json({ status: 401, message: "user not exist" });
    }
  } catch (error) {
    res.status(401).json({ status: 401, error });
  }
});

//change password
router.post("/:id/:token", async (req, res) => {
  const id = req.params.id;
  const token = req.params.token;
  try {
    const validuser = await userdb.findOne({ _id: id, verifytoken: token });
    const verifyToken = jwt.verify(token, JWT_SECRET);
    if (validuser && verifyToken._id) {
      const newpassword = await bcrypt.hash(req.body.password, 12);
      const setnewpassword = await userdb.findByIdAndUpdate(id, {
        password: newpassword,
      });
      setnewpassword.save();
      res.status(200).json({ status: 200, setnewpassword });
    } else {
      res.status(401).json({ status: 401, message: "user not exist" });
    }
  } catch (error) {
    res.status(401).json({ status: 401, error });
  }
});

module.exports = router;
