const Koa = require("koa");
const app = new Koa();
const Router = require("koa-router");
const router = new Router();
const passport = require("koa-passport");
const passportJWT = require("passport-jwt");
const LocalStrategy = require("passport-local").Strategy;
const JWTStrategy = passportJWT.Strategy;
const ExtractJwt = passportJWT.ExtractJwt;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const rewrite = require("koa-rewrite");
const views = require("koa-views");

const session = require("koa-session");

const bodyParser = require("koa-bodyparser");
const config = require("./config.js");
const knex = require("knex")(config.database);
// sessions
app.keys = config.keys;
app.use(rewrite("/", config.rewrite_url));
app.use(session(app));

// body parser
app.use(bodyParser());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  return knex("user")
    .where({ id })
    .first()
    .then(user => {
      done(null, user);
    })
    .catch(err => {
      done(err, null);
    });
});

passport.use(
  new LocalStrategy({}, (username, password, done) => {
    knex("user")
      .where({ username })
      .first()
      .then(user => {
        if (!user) return done(null, false);
        if (!bcrypt.compareSync(password, user.password)) {
          return done(null, false);
        } else {
          return done(null, user);
        }
      })
      .catch(err => {
        return done(err);
      });
  })
);

passport.use(
  "jwt",
  new JWTStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.jwt_key
    },
    (jwtPayload, done) => {
      knex("user")
        .where({ id: jwtPayload.id })
        .first()
        .then(user => {
          return done(null, user);
        })
        .catch(err => {
          return done(err);
        });
    }
  )
);
app.use(passport.initialize());
app.use(passport.session());

app.use(
  views(__dirname + "/views", {
    map: {
      html: "mustache",
      extension: "mustache"
    },
    options: {
      partials: {
        header: "header",
        footer: "footer"
      }
    }
  })
);

app.use(async (ctx, next) => {
  await next();
  const rt = ctx.response.get("X-Response-Time");
  console.log(`${ctx.method} ${ctx.url} - ${rt}`);
});

app.use(async (ctx, next) => {
  const start = Date.now();
  await next();
  const ms = Date.now() - start;
  ctx.set("X-Response-Time", `${ms}ms`);
});

function addUser(user) {
  const salt = bcrypt.genSaltSync();
  const hash = bcrypt.hashSync(user.password, salt);
  return knex("user")
    .insert({
      username: user.username,
      password: hash
    })
    .returning("*");
}
router
  .get("/auth/register", async ctx => {
    ctx.body = `
        <body>
            <h1>Register</h1>
            <form action="/auth/register" method="post">
                <p><label>username: <input type="text" name="username"></label></p>
                <p><label>passport: <input type="password" name="password"></label></p>
                <p><button type="submit">Register</button></p>
            </form>
            <a href="/auth/login">login</a>
        </body>
    `;
  })
  .post("/auth/register", async ctx => {
    const user = await addUser(ctx.request.body);
    return passport.authenticate("local", (err, user, info, status) => {
      if (user) {
        ctx.login(user);
        ctx.redirect(`/user/current`);
      } else {
        ctx.status = 400;
        ctx.body = { status: "error" };
      }
    })(ctx);
  })
  .get("/auth/login", async ctx => {
    if (!ctx.isAuthenticated()) {
      await ctx.render("login.mustache");
    } else {
      ctx.redirect("/user/current");
    }
  })
  .post("/auth/login", async ctx => {
    return passport.authenticate("local", (err, user, info, status) => {
      if (user) {
        ctx.login(user);
        ctx.redirect(`/user/current`);
      } else {
        ctx.status = 400;
        ctx.body = { status: "error" };
      }
    })(ctx);
  })
  .get("/auth/logout", async ctx => {
    if (ctx.isAuthenticated()) {
      ctx.logout();
      ctx.redirect("/auth/login");
    } else {
      ctx.body = { success: false };
      ctx.throw(401);
    }
  })

  .get("/user/current", async ctx => {
    if (ctx.isAuthenticated()) {
      const currentUser = ctx.state.user;
      const post = await knex("post").where({ author: currentUser.id }).orderBy('id', 'desc');
      const temp = post.map(p => ({
        ...p,
        content: p.content
      }));
      await ctx.render("post.mustache", {
        post: temp,
        login: true
      });
    } else {
      ctx.redirect(`/auth/login`);
    }
  })
  .get("/user/:id", async ctx => {
    const user = await knex("user")
      .where({ id: ctx.params.id })
      .first();
    if (ctx.isAuthenticated() && user.id === ctx.state.user.id) {
      ctx.redirect("/user/current");
    } else {
      const post = await knex("post").where({ author: ctx.params.id }).orderBy('id', 'desc');
      const temp = post.map(p => ({
        ...p,
        content: p.content.substring(0, 400)
      }));
      if (user) {
        await ctx.render("post.mustache", {
          post: temp,
          login: ctx.isAuthenticated()
        });
      } else {
        ctx.status = 404;
      }
    }
  })
  .get("/user/:id/post", async ctx => {
    const post = await knex("post").where({ author: ctx.params.id });
    ctx.body = { post: post };
  })
  .get("/post/edit", async ctx => {
    if (ctx.isAuthenticated()) {
      await ctx.render("edit.mustache", {
        login: true
      });
    } else {
      ctx.redirect("/auth/login");
    }
  })
  .get("/post/:id", async ctx => {
    const post = await knex("post")
      .where({ id: ctx.params.id })
      .first();
    if (post) {
      await ctx.render("detail.mustache", {
        post,
        login: ctx.isAuthenticated()
      });
    } else {
      ctx.status = 404;
    }
  })
  .post("/post/:id/delete", async ctx => {
    if (ctx.isAuthenticated()) {
      const post = await knex("post")
        .where({ id: ctx.params.id })
        .first();
      if (post && ctx.state.user.id === post.author) {
        await knex("post")
          .where({ id: ctx.params.id })
          .first()
          .delete("*");
        ctx.redirect("/user/current");
      } else {
        ctx.status = 401;
      }
    } else {
      ctx.status = 401;
    }
  })
  .get("/post/:id/edit", async ctx => {
    if (ctx.isAuthenticated()) {
      const post = await knex("post")
        .where({ id: ctx.params.id })
        .first();
      if (post && ctx.state.user.id === post.author) {
        await ctx.render("edit.mustache", {
          login: true,
          post,
          edit: true
        });
      } else {
        ctx.status = 401;
      }
    } else {
      ctx.status = 401;
    }
  })
  .post("/post/:id/edit", async ctx => {
    if (ctx.isAuthenticated()) {
      const post = await knex("post")
        .where({ id: ctx.params.id })
        .first();
      if (post && ctx.state.user.id === post.author) {
        await knex("post")
          .where({ id: ctx.params.id })
          .first()
          .update({
            title: ctx.request.body.title,
            content: ctx.request.body.content
          });
        ctx.redirect(`/post/${ctx.params.id}`);
      } else {
        ctx.status = 401;
      }
    } else {
      ctx.status = 401;
    }
  })
  .post("/post/edit", async ctx => {
    if (ctx.isAuthenticated()) {
      const currentUser = ctx.state.user.id;
      const post = await knex("post")
        .insert({
          title: ctx.request.body.title,
          content: ctx.request.body.content,
          author: currentUser
        })
        .returning("*");
      if (post) {
        ctx.status = 200;
        ctx.redirect(`/user/current`);
      } else {
        ctx.status = 500;
      }
    } else {
      ctx.redirect("/auth/login");
    }
  })
  .post("/api/v1/login", async ctx => {
    return passport.authenticate("local", (err, user, info, status) => {
      if (err || !user) {
        ctx.status = 400;
        ctx.body = {
          message: info ? info.message : "login failed",
          user: user
        };
      }
      ctx
        .login(user, { session: false })
        .then(() => {
          const token = jwt.sign(user, "jwt-secret");
          ctx.body = {
            token
          };
        })
        .catch(err => {
          if (err) {
            ctx.throw(err);
          }
        });
    })(ctx);
  })
  .get("/api/v1/hello", async ctx => {
    return passport.authenticate(
      "jwt",
      { session: false },
      (error, user, info, status) => {
        if (user) {
          ctx.body = {
            hello: "world"
          };
        } else {
          ctx.status = 401;
          ctx.body = {
            hello: "hell"
          };
        }
      }
    )(ctx);
  });

app.use(router.routes()).use(router.allowedMethods());

app.listen(3000);
