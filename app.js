/* eslint-disable func-names */
/* eslint-disable prefer-arrow-callback */
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
require("dotenv").config({ path: path.resolve(__dirname, "./.env") });
const bcrypt = require("bcryptjs");

const { Schema } = mongoose;

const mongoDb = process.env.MONGODB_URI;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
  })
);

const app = express();
app.set("views", path.join(__dirname, "./views"));
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          // passwords match! log user in
          return done(null, user);
        }
        // passwords do not match!
        return done(null, false, { message: "Incorrect password" });
      });
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => {
  res.render("index", { user: req.user });
});
app.get("/sign-up", (req, res) => res.render("sign-up-form"));
app.get("/log-out", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.listen(3000, () => console.log("app listening on port 3000!"));

app.post("/sign-up", async (req, res, next) => {
  try {
    const password = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      username: req.body.username,
      password,
    });
    await user.save();
    res.redirect("/");
  } catch (err) {
    next(err);
  }
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/sign-up",
    failureRedirect: "/",
  })
);
