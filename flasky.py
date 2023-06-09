import os
from dotenv import load_dotenv

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

COV = None
if os.environ.get('FLASK_COVERAGE'):
    import coverage
    COV = coverage.coverage(branch=True, include='app/*')
    COV.start()

import sys
import click
from flask_migrate import Migrate, upgrade, MigrateCommand
from flask_script import Manager, Shell, Command, Option
from app import create_app, db
from app.models import User, Follow, Role, Permission, Post, Comment

app = create_app(os.getenv('FLASK_CONFIG') or 'default')
migrate = Migrate(app, db)
manager = Manager(app)

@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Follow=Follow, Role=Role,
                Permission=Permission, Post=Post, Comment=Comment)

class Test(Command):
    option_list = (
        Option('--coverage/--no-coverage', dest='coverage', default=False,
            help='Run tests under code coverage.'),
        Option('--tests', '-t', dest='test_names', nargs=-1,
            help='Run only particular tests.')
    )

    def run(self, coverage, test_names):
        """Run the unit tests."""
        if coverage and not os.environ.get('FLASK_COVERAGE'):
            import subprocess
            os.environ['FLASK_COVERAGE'] = '1'
            sys.exit(subprocess.call(sys.argv))

        import unittest
        if test_names:
            tests = unittest.TestLoader().loadTestsFromNames(test_names)
        else:
            tests = unittest.TestLoader().discover('tests')
        unittest.TextTestRunner(verbosity=2).run(tests)
        if COV:
            COV.stop()
            COV.save()
            print('Coverage Summary:')
            COV.report()
            basedir = os.path.abspath(os.path.dirname(__file__))
            covdir = os.path.join(basedir, 'tmp/coverage')
            COV.html_report(directory=covdir)
            print('HTML version: file://%s/index.html' % covdir)
            COV.erase()

class Profile(Command):
    option_list = (
        Option('--length', '-l', dest='length', default=25,
            help='Number of functions to include in the profiler report.'),
        Option('--profile-dir', '-d', dest='profile_dir', default=None,
            help='Directory where profiler data files are saved.')
    )

    def run(self, length, profile_dir):
        """Start the application under the code profiler."""
        from werkzeug.middleware.profiler import ProfilerMiddleware
        app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[length],
            profile_dir=profile_dir)
        app.run()


class Deploy(Command):
    def run(self):
        """Run deployment tasks."""
        # # migrate database to latest revision
        # upgrade()

        # create or update user roles
        Role.insert_roles()

        # ensure all users are following themselves
        User.add_self_follows()


manager.add_command('db', MigrateCommand)
manager.add_command('shell', Shell(make_context=make_shell_context))
manager.add_command('runtests', Test())
manager.add_command('runprofiler', Profile())
manager.add_command('rundeployment', Deploy())

if __name__ == '__main__':
    manager.run()