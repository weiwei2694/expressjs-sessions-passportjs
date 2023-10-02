const express = require("express");
const session = require("express-session");
const passport = require("passport");
const expressLayouts = require("express-ejs-layouts");
const path = require("path");
const prisma = require("./prisma");
const flash = require('express-flash')
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// view engine
app.set('view engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(flash())
app.use(expressLayouts);
app.set("views", path.join(__dirname, "views"));

// session
app.use(
	session({
		secret: process.env.SESSION_SECRET,
		resave: false,
		saveUninitialized: false,
	})
);

// passport
app.use(passport.initialize());
app.use(passport.session());

passport.use(
	new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
  }, async function (email, password, done) {
		try {
			const user = await prisma.user.findFirst({
				where: { email },
			});
			if (!user) return done(null, false, { message: "email incorrect" });

			if (await bcrypt.compare(password, user.password)) {
				return done(null, user);
			} else {
				return done(null, false, { message: "password incorrect" });
			}
		} catch (error) {
			done(error);
		}
	})
);

passport.serializeUser(function (user, done) {
	process.nextTick(function () {
		return done(null, user.id);
	});
});

passport.deserializeUser(function (id, done) {
	process.nextTick(async function () {
		try {
			const existingUser = await prisma.user.findUnique({
				where: { id },
			});

			done(null, existingUser);
		} catch (error) {
			done(error);
		}
	});
});

const checkAuthenticate = (req, res, next) => {
	if (req.isAuthenticated()) return next();
	res.redirect("/login");
};

const checkNotAuthenticate = (req, res, next) => {
	if (req.isAuthenticated()) return res.redirect("/");
	next();
};

app.get("/", checkAuthenticate, (req, res) => {
	res.render("home", {
    user: req.user
  });
});

app.get("/profile", checkAuthenticate, (req, res) => {
	res.render("profile", {
    user: req.user
  });
});

app.get("/login", checkNotAuthenticate, (req, res) => {
	res.render("login");
});
app.post(
	"/login",
	checkNotAuthenticate,
	passport.authenticate("local", { 
      successRedirect: '/',
      failureRedirect: '/login',
      failureFlash: true
  })
);
app.get("/register", checkNotAuthenticate, (req, res) => {
	res.render("register");
});
app.post("/register", async (req, res) => {
	const { name, email, password } = req.body;
	if (!name) {
		return res.render("register", {
			error: "name required",
			name,
			email,
			password,
		});
	}
	if (!email) {
		return res.render("register", {
			error: "email required",
			name,
			email,
			password,
		});
	}
	if (!password) {
		return res.render("register", {
			error: "password required",
			name,
			email,
			password,
		});
	}

	const existingUser = await prisma.user.findFirst({
		where: { email },
	});

	if (existingUser) {
		return res.render("register", {
			error: "email already taken",
			name,
			email,
			password,
		});
	}

	const hashPassword = await bcrypt.hash(password, 10);

	await prisma.user.create({
		data: {
			name,
			email,
			password: hashPassword,
		},
	});

	res.render("register", {
		success_msg: "Register Succesfully",
	});
});

app.listen(process.env.PORT);
