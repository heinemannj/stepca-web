from app.extensions import db


class Admins(db.Model):
    __tablename__ = 'admins'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)


class Provisioners(db.Model):
    __tablename__ = 'provisioners'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)


class AuthorityPolicies(db.Model):
    __tablename__ = 'authority_policies'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)


class Nonces(db.Model):
    __tablename__ = 'nonces'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)


class UsedOtt(db.Model):
    __tablename__ = 'used_ott'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)
