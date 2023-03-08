const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
// Package documentation - https://www.npmjs.com/package/connect-mongo
const MongoStore = require("connect-mongo");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");
let crypto = require("crypto");

/**
 * -------------- GENERAL SETUP ----------------
 */
// Gives us access to variables set in the .env file via `process.env.VARIABLE_NAME` syntax
require("dotenv").config();
// Create the Express application
var app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

// Middleware that allows Express to parse through both JSON and x-www-form-urlencoded request bodies
// These are the same as `bodyParser` - you probably would see bodyParser put here in most apps
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const connection = mongoose.createConnection(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
// Creates simple schema for a User.  The hash and salt are derived from the user's given password when they register
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
});
// Defines the model that we will use in the app
const User = connection.model("User", UserSchema);
let sessionStore = MongoStore.create({ mongoUrl: process.env.MONGO_URI });

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    store: sessionStore,
    cookie: {
      maxAge: 1000 * 30,
    },
  })
);

function validPassword(password, hash, salt) {
  const hashVerify = crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");
  return hash === hashVerify;
}

function genPassword(password) {
  const salt = crypto.randomBytes(32).toString("hex");
  const genHash = crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");

  return {
    salt: salt,
    hash: genHash,
  };
}

passport.use(
  new LocalStrategy(function (username, password, cb) {
    User.findOne({ username: username })
      .then((user) => {
        if (!user) {
          return cb(null, false);
        }

        const isValid = bcrypt.compare(password, user.password);

        if (isValid) {
          return cb(null, user);
        } else {
          return cb(null, false, { message: "Incorrect password" });
        }
      })
      .catch((err) => {
        cb(err);
      });
  })
);

passport.serializeUser(function (user, cb) {
  cb(null, user.id);
});

passport.deserializeUser(function (id, cb) {
  User.findById(id)
    .then((user) => {
      cb(null, user);
    })
    .catch((err) => {
      if (err) {
        cb(err);
      }
    });
});

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res, next) => {
  res.render("index", { user: req.user });
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

app.get("/log-out", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/register", (req, res, next) => {
  res.render("sign-up-form");
});

app.post("/register", (req, res, next) => {
  bcrypt.hash("somePassword", 10, (err, hashedPassword) => {
    if (err) {
      return next(err);
    }

    const newUser = new User({
      username: req.body.username,
      password: hashedPassword,
    });

    newUser.save().then((user) => {
      console.log(user);
    });
    res.redirect("/");
  });
});

app.get("/protected-route", (req, res, next) => {
  console.log(req.session);
  if (req.isAuthenticated()) {
    res.send("<h1>You are authenticated</h1>");
  } else {
    res.send("<h1>You are not authenticated</h1>");
  }
});

app.listen(3000);
