from app.extensions import db


class SshCerts(db.Model):
    __tablename__ = 'ssh_certs'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)


class SshHostPrincipals(db.Model):
    __tablename__ = 'ssh_host_principals'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)


class SshHosts(db.Model):
    __tablename__ = 'ssh_hosts'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)


class SshUsers(db.Model):
    __tablename__ = 'ssh_users'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)


class RevokedSshCerts(db.Model):
    __tablename__ = 'revoked_ssh_certs'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)
