from datetime import datetime, date
from functools import wraps
from io import StringIO
import csv

from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)

from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"


# -------------------- MODELS --------------------
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)

    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # admin / user
    active = db.Column(db.Boolean, nullable=False, default=True)

    def set_password(self, pwd: str):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd: str) -> bool:
        return check_password_hash(self.password_hash, pwd)


class Company(db.Model):
    __tablename__ = "companies"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)


class Project(db.Model):
    __tablename__ = "projects"
    id = db.Column(db.Integer, primary_key=True)

    company_id = db.Column(db.Integer, db.ForeignKey("companies.id"), nullable=False)
    name = db.Column(db.String(160), nullable=False)

    company = db.relationship("Company", backref="projects")

    __table_args__ = (
        db.UniqueConstraint("company_id", "name", name="uq_project_company_name"),
    )


class TimeEntry(db.Model):
    __tablename__ = "time_entries"
    id = db.Column(db.Integer, primary_key=True)

    company_id = db.Column(db.Integer, db.ForeignKey("companies.id"), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False)

    work_date = db.Column(db.Date, nullable=False, default=date.today)
    hours = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(400), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    company = db.relationship("Company")
    project = db.relationship("Project")


# -------------------- SEED --------------------
def seed_data():
    if Company.query.count() == 0:
        db.session.add_all([Company(name="Activité A"), Company(name="Activité B")])
        db.session.commit()

    if User.query.count() == 0:
        admin = User(username="admin", email="admin@example.com", role="admin", active=True)
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()


# -------------------- APP --------------------
def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "dev-secret-change-me"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        db.create_all()
        seed_data()

    # --- Flask-Login loader (SQLAlchemy 2.x friendly)
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))
    
    # --- Flask Health 4 render
    @app.get("/health")
    def health():
         return {"status": "ok"}
    
    # --- aide

    @app.get("/help")
    @login_required
    def help_page():
        return render_template("help.html")



    # --- Role decorator
    def role_required(role: str):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                if not current_user.is_authenticated:
                    return login_manager.unauthorized()
                if current_user.role != role:
                    flash("Accès refusé.", "error")
                    return redirect(url_for("dashboard"))
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    # --- Password reset helpers
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

    def generate_reset_token(email: str) -> str:
        return serializer.dumps(email, salt="pwd-reset")

    def verify_reset_token(token: str, max_age_seconds: int = 3600):
        try:
            return serializer.loads(token, salt="pwd-reset", max_age=max_age_seconds)
        except (SignatureExpired, BadSignature):
            return None

    # ---------------- AUTH ----------------
    @app.get("/login")
    def login():
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username, active=True).first()
        if not user or not user.check_password(password):
            flash("Identifiants invalides.", "error")
            return redirect(url_for("login"))

        login_user(user)
        flash("Connecté.", "ok")
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Déconnecté.", "ok")
        return redirect(url_for("login"))

    @app.get("/favicon.ico")
    def favicon():
        return ("", 204)

    # ---------------- CHANGE PASSWORD (connected user) ----------------
    @app.get("/change-password")
    @login_required
    def change_password():
        return render_template("change_password.html")

    @app.post("/change-password")
    @login_required
    def change_password_post():
        current_pwd = request.form.get("current_password", "")
        new_pwd1 = request.form.get("new_password1", "")
        new_pwd2 = request.form.get("new_password2", "")

        if not current_user.check_password(current_pwd):
            flash("Ancien mot de passe incorrect.", "error")
            return redirect(url_for("change_password"))

        if len(new_pwd1) < 6:
            flash("Nouveau mot de passe trop court (6 caractères min).", "error")
            return redirect(url_for("change_password"))

        if new_pwd1 != new_pwd2:
            flash("Les nouveaux mots de passe ne correspondent pas.", "error")
            return redirect(url_for("change_password"))

        user = db.session.get(User, int(current_user.id))
        user.set_password(new_pwd1)
        db.session.commit()

        flash("Mot de passe mis à jour ✅", "ok")
        return redirect(url_for("dashboard"))

    # ---------------- Forgot / Reset password ----------------
    @app.get("/forgot-password")
    def forgot_password():
        return render_template("forgot_password.html")

    @app.post("/forgot-password")
    def forgot_password_post():
        email = request.form.get("email", "").strip().lower()

        flash("Si un compte existe avec cet email, un lien de réinitialisation a été généré.", "ok")

        user = User.query.filter_by(email=email, active=True).first()
        if user:
            token = generate_reset_token(email)
            reset_link = url_for("reset_password", token=token, _external=True)

            # DEV: affichage console
            print("\n=== RESET LINK (DEV) ===")
            print(reset_link)
            print("========================\n")

        return redirect(url_for("login"))

    @app.get("/reset-password/<token>")
    def reset_password(token):
        email = verify_reset_token(token, max_age_seconds=3600)
        if not email:
            flash("Lien invalide ou expiré.", "error")
            return redirect(url_for("forgot_password"))
        return render_template("reset_password.html", token=token)

    @app.post("/reset-password/<token>")
    def reset_password_post(token):
        email = verify_reset_token(token, max_age_seconds=3600)
        if not email:
            flash("Lien invalide ou expiré.", "error")
            return redirect(url_for("forgot_password"))

        password1 = request.form.get("password1", "")
        password2 = request.form.get("password2", "")

        if len(password1) < 6:
            flash("Mot de passe trop court (6 caractères min).", "error")
            return redirect(url_for("reset_password", token=token))

        if password1 != password2:
            flash("Les mots de passe ne correspondent pas.", "error")
            return redirect(url_for("reset_password", token=token))

        user = User.query.filter_by(email=email, active=True).first()
        if not user:
            flash("Compte introuvable ou inactif.", "error")
            return redirect(url_for("forgot_password"))

        user.set_password(password1)
        db.session.commit()

        flash("Mot de passe mis à jour. Tu peux te connecter.", "ok")
        return redirect(url_for("login"))

    # ---------------- ROOT / DASHBOARD ----------------
    @app.get("/")
    def root():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        total_all = db.session.query(func.coalesce(func.sum(TimeEntry.hours), 0.0)).scalar() or 0.0
        today = date.today()
        month_start = date(today.year, today.month, 1)

        total_month = (
            db.session.query(func.coalesce(func.sum(TimeEntry.hours), 0.0))
            .filter(TimeEntry.work_date >= month_start)
            .scalar() or 0.0
        )

        per_company = (
            db.session.query(Company.name, func.sum(TimeEntry.hours))
            .join(TimeEntry, TimeEntry.company_id == Company.id)
            .group_by(Company.name)
            .order_by(func.sum(TimeEntry.hours).desc())
            .all()
        )

        last_entries = (
            TimeEntry.query
            .order_by(TimeEntry.work_date.desc(), TimeEntry.created_at.desc())
            .limit(10)
            .all()
        )

        labels = [name for (name, h) in per_company]
        values = [float(h or 0) for (name, h) in per_company]

        return render_template(
            "dashboard.html",
            total_all=total_all,
            total_month=total_month,
            per_company=per_company,
            last_entries=last_entries,
            labels=labels,
            values=values,
        )

    # ---------------- ENTRIES (User add; Admin manage all) ----------------
    @app.get("/entries/new")
    @login_required
    def entry_new():
        companies = Company.query.order_by(Company.name).all()
        projects = Project.query.join(Company).order_by(Company.name, Project.name).all()
        return render_template("entry_form.html", entry=None, companies=companies, projects=projects)

    @app.post("/entries")
    @login_required
    def entry_create():
        company_id = request.form.get("company_id", type=int)
        project_id = request.form.get("project_id", type=int)
        work_date_str = request.form.get("work_date", "").strip()
        hours = request.form.get("hours", type=float)
        description = request.form.get("description", "").strip() or None

        if not (company_id and project_id and work_date_str and hours is not None):
            flash("Champs requis manquants.", "error")
            return redirect(url_for("entry_new"))

        try:
            work_date = datetime.strptime(work_date_str, "%Y-%m-%d").date()
        except ValueError:
            flash("Date invalide.", "error")
            return redirect(url_for("entry_new"))

        if hours <= 0:
            flash("Les heures doivent être > 0.", "error")
            return redirect(url_for("entry_new"))

        proj = Project.query.get_or_404(project_id)
        if proj.company_id != company_id:
            flash("Le projet ne correspond pas à l'entreprise.", "error")
            return redirect(url_for("entry_new"))

        db.session.add(TimeEntry(
            company_id=company_id,
            project_id=project_id,
            work_date=work_date,
            hours=hours,
            description=description
        ))
        db.session.commit()
        flash("Saisie enregistrée.", "ok")
        return redirect(url_for("dashboard"))

    @app.get("/entries")
    @login_required
    @role_required("admin")
    def entries_list():
        entries = TimeEntry.query.order_by(TimeEntry.work_date.desc(), TimeEntry.created_at.desc()).all()
        return render_template("entries.html", entries=entries)

    @app.get("/entries/<int:entry_id>/edit")
    @login_required
    @role_required("admin")
    def entry_edit(entry_id: int):
        entry = TimeEntry.query.get_or_404(entry_id)
        companies = Company.query.order_by(Company.name).all()
        projects = Project.query.join(Company).order_by(Company.name, Project.name).all()
        return render_template("entry_form.html", entry=entry, companies=companies, projects=projects)

    @app.post("/entries/<int:entry_id>/update")
    @login_required
    @role_required("admin")
    def entry_update(entry_id: int):
        entry = TimeEntry.query.get_or_404(entry_id)

        company_id = request.form.get("company_id", type=int)
        project_id = request.form.get("project_id", type=int)
        work_date_str = request.form.get("work_date", "").strip()
        hours = request.form.get("hours", type=float)
        description = request.form.get("description", "").strip() or None

        if not (company_id and project_id and work_date_str and hours is not None):
            flash("Champs requis manquants.", "error")
            return redirect(url_for("entry_edit", entry_id=entry_id))

        try:
            work_date = datetime.strptime(work_date_str, "%Y-%m-%d").date()
        except ValueError:
            flash("Date invalide.", "error")
            return redirect(url_for("entry_edit", entry_id=entry_id))

        if hours <= 0:
            flash("Les heures doivent être > 0.", "error")
            return redirect(url_for("entry_edit", entry_id=entry_id))

        proj = Project.query.get_or_404(project_id)
        if proj.company_id != company_id:
            flash("Le projet ne correspond pas à l'entreprise.", "error")
            return redirect(url_for("entry_edit", entry_id=entry_id))

        entry.company_id = company_id
        entry.project_id = project_id
        entry.work_date = work_date
        entry.hours = hours
        entry.description = description
        db.session.commit()

        flash("Saisie mise à jour.", "ok")
        return redirect(url_for("entries_list"))

    @app.post("/entries/<int:entry_id>/delete")
    @login_required
    @role_required("admin")
    def entry_delete(entry_id: int):
        entry = TimeEntry.query.get_or_404(entry_id)
        db.session.delete(entry)
        db.session.commit()
        flash("Saisie supprimée.", "ok")
        return redirect(url_for("entries_list"))

    # ---------------- REPORT + EXPORT ----------------
    @app.get("/report")
    @login_required
    def report():
        companies = Company.query.order_by(Company.name).all()
        projects = Project.query.join(Company).order_by(Company.name, Project.name).all()

        company_id = request.args.get("company_id", type=int)
        project_id = request.args.get("project_id", type=int)
        date_from = request.args.get("date_from", "").strip()
        date_to = request.args.get("date_to", "").strip()

        q = TimeEntry.query
        if company_id:
            q = q.filter(TimeEntry.company_id == company_id)
        if project_id:
            q = q.filter(TimeEntry.project_id == project_id)

        if date_from:
            try:
                df = datetime.strptime(date_from, "%Y-%m-%d").date()
                q = q.filter(TimeEntry.work_date >= df)
            except ValueError:
                flash("date_from invalide.", "error")

        if date_to:
            try:
                dt = datetime.strptime(date_to, "%Y-%m-%d").date()
                q = q.filter(TimeEntry.work_date <= dt)
            except ValueError:
                flash("date_to invalide.", "error")

        entries = q.order_by(TimeEntry.work_date.desc()).all()
        total_hours = q.with_entities(func.coalesce(func.sum(TimeEntry.hours), 0.0)).scalar() or 0.0

        per_project = (
            q.join(Project)
             .with_entities(Project.name, func.sum(TimeEntry.hours))
             .group_by(Project.name)
             .order_by(func.sum(TimeEntry.hours).desc())
             .all()
        )

        return render_template(
            "report.html",
            companies=companies,
            projects=projects,
            entries=entries,
            total_hours=total_hours,
            per_project=per_project,
            filters=dict(company_id=company_id, project_id=project_id, date_from=date_from, date_to=date_to),
        )

    @app.get("/export.csv")
    @login_required
    def export_csv():
        company_id = request.args.get("company_id", type=int)
        project_id = request.args.get("project_id", type=int)
        date_from = request.args.get("date_from", "").strip()
        date_to = request.args.get("date_to", "").strip()

        q = TimeEntry.query.join(Company).join(Project)

        if company_id:
            q = q.filter(TimeEntry.company_id == company_id)
        if project_id:
            q = q.filter(TimeEntry.project_id == project_id)

        if date_from:
            try:
                df = datetime.strptime(date_from, "%Y-%m-%d").date()
                q = q.filter(TimeEntry.work_date >= df)
            except ValueError:
                pass

        if date_to:
            try:
                dt = datetime.strptime(date_to, "%Y-%m-%d").date()
                q = q.filter(TimeEntry.work_date <= dt)
            except ValueError:
                pass

        rows = (
            q.with_entities(
                TimeEntry.work_date,
                Company.name.label("company"),
                Project.name.label("project"),
                TimeEntry.hours,
                TimeEntry.description
            )
            .order_by(TimeEntry.work_date.asc())
            .all()
        )

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["date", "entreprise", "projet", "heures", "description"])
        for r in rows:
            writer.writerow([r.work_date.isoformat(), r.company, r.project, r.hours, r.description or ""])

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=suivi_heures.csv"},
        )

    # ---------------- ADMIN: COMPANIES ----------------
    @app.get("/companies")
    @login_required
    @role_required("admin")
    def companies_list():
        companies = Company.query.order_by(Company.name).all()
        return render_template("companies.html", companies=companies)

    @app.post("/companies")
    @login_required
    @role_required("admin")
    def companies_create():
        name = request.form.get("name", "").strip()
        if not name:
            flash("Nom entreprise requis.", "error")
            return redirect(url_for("companies_list"))
        try:
            db.session.add(Company(name=name))
            db.session.commit()
            flash("Entreprise ajoutée.", "ok")
        except Exception:
            db.session.rollback()
            flash("Entreprise déjà existante ou erreur.", "error")
        return redirect(url_for("companies_list"))

    @app.post("/companies/<int:company_id>/delete")
    @login_required
    @role_required("admin")
    def companies_delete(company_id: int):
        c = Company.query.get_or_404(company_id)
        TimeEntry.query.filter_by(company_id=c.id).delete()
        Project.query.filter_by(company_id=c.id).delete()
        db.session.delete(c)
        db.session.commit()
        flash("Entreprise supprimée.", "ok")
        return redirect(url_for("companies_list"))

    # ---------------- ADMIN: PROJECTS ----------------
    @app.get("/projects")
    @login_required
    @role_required("admin")
    def projects_list():
        companies = Company.query.order_by(Company.name).all()
        projects = Project.query.join(Company).order_by(Company.name, Project.name).all()
        return render_template("projects.html", projects=projects, companies=companies)

    @app.post("/projects")
    @login_required
    @role_required("admin")
    def projects_create():
        company_id = request.form.get("company_id", type=int)
        name = request.form.get("name", "").strip()
        if not company_id or not name:
            flash("Entreprise + nom projet requis.", "error")
            return redirect(url_for("projects_list"))
        try:
            db.session.add(Project(company_id=company_id, name=name))
            db.session.commit()
            flash("Projet ajouté.", "ok")
        except Exception:
            db.session.rollback()
            flash("Projet déjà existant (pour cette entreprise) ou erreur.", "error")
        return redirect(url_for("projects_list"))

    @app.post("/projects/<int:project_id>/delete")
    @login_required
    @role_required("admin")
    def projects_delete(project_id: int):
        p = Project.query.get_or_404(project_id)
        TimeEntry.query.filter_by(project_id=p.id).delete()
        db.session.delete(p)
        db.session.commit()
        flash("Projet supprimé.", "ok")
        return redirect(url_for("projects_list"))

    # ---------------- ADMIN: USERS ----------------
    @app.get("/users")
    @login_required
    @role_required("admin")
    def users_list():
        users = User.query.order_by(User.username).all()
        return render_template("users.html", users=users)

    @app.post("/users")
    @login_required
    @role_required("admin")
    def users_create():
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "user").strip()

        if not username or not email or not password or role not in ("admin", "user"):
            flash("Champs invalides.", "error")
            return redirect(url_for("users_list"))

        if User.query.filter_by(username=username).first():
            flash("Username déjà utilisé.", "error")
            return redirect(url_for("users_list"))

        if User.query.filter_by(email=email).first():
            flash("Email déjà utilisé.", "error")
            return redirect(url_for("users_list"))

        u = User(username=username, email=email, role=role, active=True)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash("Utilisateur créé.", "ok")
        return redirect(url_for("users_list"))

    @app.post("/users/<int:user_id>/toggle")
    @login_required
    @role_required("admin")
    def users_toggle(user_id: int):
        u = User.query.get_or_404(user_id)
        if u.username == "admin":
            flash("Impossible de désactiver admin.", "error")
            return redirect(url_for("users_list"))
        u.active = not u.active
        db.session.commit()
        flash("Statut modifié.", "ok")
        return redirect(url_for("users_list"))

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
