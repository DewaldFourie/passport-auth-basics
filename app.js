const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const { log } = require("console");
const Schema = mongoose.Schema;
const bcrypt = require("bcryptjs");


// get data base through URL and connect to it
const mongoDb = "mongodb+srv://dewaldfourie08:WtWfgU!RH5J8bcN@cluster0.ewk5etm.mongodb.net/passport_authentication?retryWrites=true&w=majority";
mongoose.connect(mongoDb);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

// create a new Schema Model for a user (This should ideally be in a separate file)
const User = mongoose.model(
    "User",
    new Schema({
        username: { type: String, required: true },
        password: { type: String, required: true },
    })
);

// setting app express and view engine PUG
const app = express();
app.set("views", __dirname);
app.set("view engine", "pug");
app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

// creating a local variable for usage in views 
app.use((req, res, next) => {
    res.locals.currentUser = req.user;
    next();
});

// main get route
app.get("/", (req, res) => {
    res.render("index", { user: req.user });
});

// sign up routes
app.get("/sign-up", (req, res) => res.render("sign-up-form"));
app.post("/sign-up", async(req, res, next) => {
    try {
        // hash function for password salting
        bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
            // if hash error > return next err
            if (err) {
                return next (err)
            }
            // else create a new user with username and hashed password 
            const user = new User({
                username: req.body.username,
                password: hashedPassword,
            });
            // save new user to db
            await user.save();
            res.redirect("/");
        });
    } catch(err) {
        return next(err);
    };
});

app.listen(3000, () => console.log("app listening on port 3000!"));

// using passport with the LocalStrategy to handle login functionality
passport.use(
    new LocalStrategy(async (username, password, done) => {
        try {
            const user = await User.findOne({ username: username });
            if (!user) {
                return done(null, false, { message: "Incorrect Username" });
            }
            const match = await bcrypt.compare(password, user.password)
            if (!match) {
                return done(null, false, { message: "Incorrect Password" });
            };
            return done(null, user);
        } catch(err) {
            return done(err)
        };
    })
);

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch(err) {
        done(err);
    };
});

// login route en redirect options
app.post("/log-in", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
}))

// logout route and redirect options
app.get("/log-out", (req, res, next) => {
    req.logout((err) => {
        if(err) {
            return next(err);
        }
        res.redirect("/");
    });
});

