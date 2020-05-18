const BEBOP_LOCAL_STORAGE_TOKEN_KEY = "bebop_auth_token";
const BEBOP_OAUTH_RESULT_COOKIE = "bebop_oauth_result";

var BebopApp = new Vue({
  el: "#app",

  template: `
    <div>
      <bebop-nav :config="config" :auth="auth"></bebop-nav>
      <bebop-username-modal ref="usernameModal"></bebop-username-modal>
      <router-view :config="config" :auth="auth"></router-view>
    </div>
  `,

  router: new VueRouter({
    routes: [
      { path: "/", component: BebopTopics },
      { path: "/p/:page", component: BebopTopics },
      { path: "/t/:topic", component: BebopComments },
      { path: "/t/:topic/p/:page", component: BebopComments },
      { path: "/t/:topic/p/:page/c/:comment", component: BebopComments },
      { path: "/new-topic", component: BebopNewTopic },
      { path: "/new-comment/:topic", component: BebopNewComment },
      { path: "/me", component: BebopUser },
      { path: "/u/:user", component: BebopUser },
    ],
    scrollBehavior: function(to, from, savedPosition) {
      if (savedPosition) {
        return savedPosition;
      } else {
        return { x: 0, y: 0 };
      }
    },
  }),

  data: function() {
    return {
      config: {
        title: "",
        oauth: [],
      },
      auth: {
        authenticated: false,
        user: {},
      },
    };
  },

  mounted: function() {
    this.getConfig()
    this.checkAuth();
  },

  methods: {
    getConfig: function() {
      this.$http.get("config.json").then(
        response => {
          this.config = response.body;
          if (this.config.title) {
            document.title = this.config.title;
          }
        },
        response => {
          console.log("ERROR: getConfig: " + response.status);
        }
      );
    },

    signUp: function(provider) {
      alert("in signUp")
      if (provider == "email") {
        var email = $("#login").val().trim();
        var password = $("#password").val().trim();
        this.$http
        .post("oauth/emailSignUp", {
          email: email,
          password: password,
        })
        .then(
          response => {
            if (response.data == "success") {
              BebopApp.oauthEnd()
            } else {
              alert("not success")
            }
            // this.$parent.$router.push("/t/" + response.data.id);
          },
          response => {
            this.posting = false;
            this.showErrorMessage("An error occured");
            console.log("ERROR: postTopic: " + JSON.stringify(response.body));
          }
        );
      } else {
        window.open("oauth/begin/" + provider, "", "width=800,height=600");
      }
      
    },

    signIn: function(provider) {
      alert("in signIn")
      if (provider == "email") {
        var email = $("#login").val().trim();
        var password = $("#password").val().trim();
        this.$http
        .post("oauth/emailSignIn", {
          email: email,
          password: password,
        })
        .then(
          response => {
            if (response.data == "success") {
              BebopApp.oauthEnd()
            } else {
              alert(response.data)
            }
            // this.$parent.$router.push("/t/" + response.data.id);
          },
          response => {
            this.posting = false;
            this.showErrorMessage("An error occured");
            console.log("ERROR: postTopic: " + JSON.stringify(response.body));
          }
        );
      } else {
        window.open("oauth/begin/" + provider, "", "width=800,height=600");
      }
      
    },

    signOut: function() {
      localStorage.removeItem(BEBOP_LOCAL_STORAGE_TOKEN_KEY);
      Vue.http.headers.common["Authorization"] = "";
      this.auth = {
        authenticated: false,
        user: {},
      };
    },

    oauthEnd: function() {
      console.log("in oauthEnd")
      console.log(document.cookie)
      var result = this.getCookieByName(BEBOP_OAUTH_RESULT_COOKIE);
      var parts = result.split(":");

      console.log("in oauthEnd");
      console.log(parts);

      if (parts.length !== 2) {
        this.oauthError("Unknown");
        return;
      }

      if (parts[0] === "error") {
        this.oauthError(parts[1]);
        return;
      }

      if (parts[0] !== "success") {
        this.oauthError("Unknown");
        return;
      }

      this.oauthSuccess(parts[1]);
    },

    getCookieByName: function(name) {
      var value = "; " + document.cookie;
      var parts = value.split("; " + name + "=");
      console.log("in getCookieByName");
      console.log(value);
      console.log(parts);
      if (parts.length === 2) return parts.pop().split(";").shift();
    },

    oauthSuccess: function(token) {
      console.log("in oauthSuccess");
      console.log(token);
      localStorage.setItem(BEBOP_LOCAL_STORAGE_TOKEN_KEY, token);
      this.checkAuth();
    },

    oauthError: function(error) {
      if (error === "UserBlocked") {
        console.log("oauth error: USER IS BLOCKED");
      } else {
        console.log("oauth error: " + error);
      }
      this.signOut();
    },

    checkAuth: function() {
      console.log("in checkAuth")
      var token = localStorage.getItem(BEBOP_LOCAL_STORAGE_TOKEN_KEY);
      console.log(token)
      if (token) {
        Vue.http.headers.common["Authorization"] = "Bearer " + token;
      }
      this.getMe();
    },

    getMe: function() {
      this.$http.get("api/v1/me").then(
        response => {
          this.auth = {
            authenticated: response.body.authenticated ? true : false,
            user: response.body.authenticated ? response.body.user : {},
          };
          if (this.auth.authenticated && this.auth.user.name === "") {
            this.setMyName();
          }
        },
        response => {
          console.log("ERROR: getMe: " + JSON.stringify(response.body));
          if (response.status === 401) {
            this.signOut();
          }
        }
      );
    },

    setMyName: function() {
      this.$refs.usernameModal.show(this.auth.user.id, "", success => {
        if (!success) {
          this.signOut();
        }
        this.getMe();
      });
    },
  },
});

function bebopOAuthEnd() {
  BebopApp.oauthEnd();
}
