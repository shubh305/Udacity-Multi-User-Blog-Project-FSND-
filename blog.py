import os
import re
import hmac
import jinja2
import hashlib
import random
import webapp2

from string import letters
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Global Functions


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# get the key from user table


def users_key(group='default'):
    return db.Key.from_path('users', group)

# get the key from blog table


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# Validation for login / signup =======================================

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# Authentication ==========================================

secret = 'unhinged'

# for password encryption


def make_pw_hash(name, password, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + password + salt).hexdigest()
    return '%s,%s' % (salt, h)

# salt to secure the password


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

# password validation by hashing


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# create secure cookie values


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

# check secure cookie values


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Blog Handler


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header(
            'Set-Cookie',
            'user_id=; Path=/')

    # securely set a cookie

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # get the user from secure cookie when we initializing

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    # read the cookie

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

# User Stuff ==========================================================


# create a database to store user info

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, username, password):
        u = User.by_name(username)
        if u and valid_pw(username, password, u.pw_hash):
            return u

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

# Blog Stuff =======================================================

# create a database to store blog posts


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(default=0)

    def render(self, current_user_id):
        key = db.Key.from_path('User', int(self.user_id), parent=users_key())
        user = db.get(key)

        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self, current_user_id=current_user_id,
                          author=user.name)

    @classmethod
    def by_id(cls, uid):
        return Post.get_by_id(uid, parent=blog_key())


# create a database to store all comments

class Comment(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.IntegerProperty(required=True)
    user_name = db.TextProperty(required=True)


# create a database to store all likes

class Like(db.Model):
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

# show all the posts in the front page


class BlogFront(BlogHandler):

    def get(self):
        posts = db.GqlQuery(
            "select * from Post order by created desc limit 10")

        self.render('main-page.html', posts=posts)

# Posts ===============================================================


class Post(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = db.GqlQuery(
            '''select * from Comment where ancestor is :1
            order by created desc limit 10''', key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, comments=comments)

# Like Post ==========================================================


class LikePost(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and self.user.key().id() == post.user_id:
            error = "ERROR: You can not like your own post."
            self.render('main-page.html', access_error=error)
        elif not self.user:
            self.redirect('/login')
        else:
            user_id = self.user.key().id()
            post_id = post.key().id()

            like = Like.all().filter('user_id =', user_id).filter(
                                     'post_id =', post_id).get()

            if like:
                self.redirect('/' + str(post.key().id()))

            else:
                like = Like(parent=key,
                            user_id=self.user.key().id(),
                            post_id=post.key().id())

                post.likes += 1

                like.put()
                post.put()

                self.redirect('/' + str(post.key().id()))

# Unlike Post ========================================================


class UnlikePost(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and self.user.key().id() == post.user_id:
            self.write("You cannot dislike your own post")
        elif not self.user:
            self.redirect('/login')
        else:
            user_id = self.user.key().id()
            post_id = post.key().id()

            l = Like.all().filter('user_id =',
                                  user_id).filter('post_id =', post_id).get()

            if l:
                l.delete()
                post.likes -= 1
                post.put()

                self.redirect('/' + str(post.key().id()))
            else:
                self.redirect('/' + str(post.key().id()))

# New Post ===========================================================


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            self.render("new-post.html")
        else:
            error = "You must be signed in to create a post."
            self.render("index.html", access_error=error)

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, user_id=self.user.key().id())
            p.put()
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = "Please fill up the fields."
            self.render("new-post.html", subject=subject,
                        content=content, error=error)

# Edit Post ===========================================================


class EditPost(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and self.user.key().id() == post.user_id:
            self.render('edit-post.html', subject=post.subject,
                        content=post.content, post_id=post_id)

        elif not self.user:
            self.redirect('/login')

        else:
            self.write("You cannot edit your own posts.")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not self.user:
            return self.redirect('/login')

        if self.user and self.user.key().id() == post.user_id:
            subject = self.request.get('subject')
            content = self.request.get('content')

            if subject and content:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)

                post.subject = subject
                post.content = content

                post.put()

                self.redirect('/%s' % str(post.key().id()))
            else:
                error = "Error: Please include subject and content"
                self.render("new-post.html", subject=subject,
                            content=content, error=error)

        else:
            self.write("You cannot edit this post.")

# Delete Post =========================================================


class DeletePost(BlogHandler):

    def get(self, post_id, post_user_id):
        if self.user and self.user.key().id() == int(post_user_id):
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.delete()

            self.redirect('/')

        elif not self.user:
            self.redirect('/login')

        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            comments = db.GqlQuery(
                '''select * from Comment where ancestor is :1
                order by created desc limit 10''', key)

            error = "You don't have permission to delete this post"
            self.render("permalink.html", post=post,
                        comments=comments, error=error)

# Add Comment ========================================================


class AddComment(BlogHandler):

    def get(self, post_id, user_id):
        if not self.user:
            self.render('/login')
        else:
            self.render("new-comment.html")

    def post(self, post_id, user_id):
        if not self.user:
            return

        content = self.request.get('content')
        if content:
            user_name = self.user.name
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())

            c = Comment(parent=key, user_id=int(user_id), content=content,
                        user_name=user_name)
            c.put()

            self.redirect('/' + post_id)
        else:
            error = "Error : Please fill up the fields."
            self.render("new-comment.html",
                        content=content, error=error)


# Edit Comment ========================================================

class EditComment(BlogHandler):

    def get(self, post_id, post_user_id, comment_id):
        if self.user and self.user.key().id() == int(post_user_id):
            postKey = db.Key.from_path('Post', int(post_id), parent=blog_key())
            key = db.Key.from_path('Comment', int(comment_id), parent=postKey)
            comment = db.get(key)

            self.render('edit-comment.html', content=comment.content)

        elif not self.user:
            self.redirect('/login')

        else:
            self.write("You don't have permission to edit this comment.")

    def post(self, post_id, post_user_id, comment_id):
        if not self.user:
            return

        if self.user and self.user.key().id() == int(post_user_id):
            content = self.request.get('content')

            postKey = db.Key.from_path('Post', int(post_id), parent=blog_key())
            key = db.Key.from_path('Comment', int(comment_id), parent=postKey)
            comment = db.get(key)

            comment.content = content
            comment.put()

            self.redirect('/' + post_id)

        else:
            self.write("You don't have permission to edit this comment.")

# Delete Comment ======================================================


class DeleteComment(BlogHandler):

    def get(self, post_id, post_user_id, comment_id):

        if self.user and self.user.key().id() == int(post_user_id):
            postKey = db.Key.from_path('Post', int(post_id), parent=blog_key())
            key = db.Key.from_path('Comment', int(comment_id), parent=postKey)
            comment = db.get(key)
            comment.delete()

            self.redirect('/' + post_id)

        elif not self.user:
            self.redirect('/login')

        else:
            self.write("You don't have permission to delete this comment.")

# Login ===============================================================


class Login(BlogHandler):

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)

        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid Username or Password'
            self.render('login.html', error=msg)

# Logout ==============================================================


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/')

# Sign up =============================================================


class Signup(BlogHandler):

    def done(self):
        u = User.by_name(self.username)

        if u:
            error = 'That user already exists.'
            self.render('signup.html', error=error)

        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

    def get(self):
        self.render('signup.html')

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error'] = "Error : Invalid username"
            have_error = True

        if not valid_password(self.password):
            params['error'] = "Error : Invalid password"
            have_error = True

        elif self.password != self.verify:
            params['error'] = "Error : Your passwords didn't match"
            have_error = True

        if not valid_email(self.email):
            params['error'] = "Error : That's not a valid email"
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()


app = webapp2.WSGIApplication([
    ('/', BlogFront),
    ('/signup', Signup),
    ('/login', Login),
    ('/logout', Logout),
    ('/newpost', NewPost),
    ('/([0-9]+)', Post),
    ('/([0-9]+)/like', LikePost),
    ('/([0-9]+)/unlike', UnlikePost),
    ('/([0-9]+)/edit', EditPost),
    ('/([0-9]+)/delete/([0-9]+)', DeletePost),
    ('/([0-9]+)/addcomment/([0-9]+)', AddComment),
    ('/([0-9]+)/([0-9]+)/editcomment/([0-9]+)', EditComment),
    ('/([0-9]+)/([0-9]+)/deletecomment/([0-9]+)', DeleteComment)
    ], debug=True)
