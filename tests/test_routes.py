import pytest

# Import the application instance from your main file (app.py)
from app import app as flask_app 


# --- FIXTURES (Setup Code) ---

@pytest.fixture
def client():
    """
    Fixture to set up a Flask test client.
    This runs before every test that uses the 'client' argument.
    """
    # 1. Set Flask configuration to Testing mode
    flask_app.config['TESTING'] = True
    
    # 2. Use the test client to simulate HTTP requests
    with flask_app.test_client() as client:
        # Code before 'yield' runs before the test
        yield client
        # Code after 'yield' would run after the test (cleanup)

@pytest.fixture
def logged_in_client(client):
    """
    Fixture to simulate a client with an active, logged-in session.
    This is necessary to bypass the @login_required decorator in the tests.
    """
    with client.session_transaction() as session:
        # Mocks the 'logged_in' session variable used by your decorator
        session['logged_in'] = True 
    return client


# --- TESTS (Assertions) ---

# --- Public Route Tests ---

def test_index_page(client):
    """Test that the root index page loads successfully (status 200)."""
    response = client.get('/')
    assert response.status_code == 200

def test_login_page(client):
    """Test that the /login page loads successfully (status 200)."""
    response = client.get('/login')
    assert response.status_code == 200

def test_register_page(client):
    """Test that the /register page loads successfully (status 200)."""
    response = client.get('/register')
    assert response.status_code == 200

# --- Protected Route Tests ---

def test_dashboard_access_denied(client):
    """
    Test that an unauthorized request to /dashboard redirects to /login (status 302).
    """
    response = client.get('/dashboard')
    # Should redirect
    assert response.status_code == 302
    # Check that the redirect location is the login page
    assert '/login' in response.headers['Location']

def test_dashboard_access_allowed(logged_in_client):
    """
    Test that an authorized request (simulated logged-in session) to /dashboard works (status 200).
    """
    # Uses the 'logged_in_client' fixture, which has 'logged_in': True in the session
    response = logged_in_client.get('/dashboard')
    assert response.status_code == 200

def test_logout(logged_in_client):
    """Test that the /logout route redirects to the index page (status 302)."""
    response = logged_in_client.get('/logout')
    assert response.status_code == 302
    assert '/' in response.headers['Location']