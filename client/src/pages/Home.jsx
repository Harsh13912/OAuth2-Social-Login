// client/src/pages/Home.jsx
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

function Home() {
    const { isAuthenticated, user } = useAuth();

    return (
        <div className="min-h-screen bg-gradient-to-br from-indigo-50 via-white to-purple-50">
            {/* Hero Section */}
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
                <div className="text-center">
                    <h1 className="text-5xl md:text-6xl font-bold text-gray-900 mb-6">
                        Welcome to
                        <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-600 to-purple-600">
              {' '}OAuth Login
            </span>
                    </h1>
                    <p className="text-xl text-gray-600 mb-8 max-w-2xl mx-auto">
                        Secure, password-less authentication using Google and Facebook.
                        Sign in with just one click and get started instantly.
                    </p>

                    {isAuthenticated ? (
                        <div className="flex flex-col items-center gap-4">
                            <p className="text-lg text-gray-700">
                                Welcome back, <span className="font-semibold">{user?.name}</span>! 👋
                            </p>
                            <Link
                                to="/dashboard"
                                className="inline-block px-8 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg shadow-lg transition-colors"
                            >
                                Go to Dashboard
                            </Link>
                        </div>
                    ) : (
                        <Link
                            to="/login"
                            className="inline-block px-8 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg shadow-lg transition-colors"
                        >
                            Get Started
                        </Link>
                    )}
                </div>

                {/* Features Grid */}
                <div className="mt-20 grid md:grid-cols-3 gap-8">
                    {/* Feature 1 */}
                    <div className="bg-white rounded-xl p-6 shadow-md border border-gray-100">
                        <div className="w-12 h-12 bg-indigo-100 rounded-lg flex items-center justify-center mb-4">
                            <svg className="w-6 h-6 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                            </svg>
                        </div>
                        <h3 className="text-xl font-bold text-gray-900 mb-2">Secure Authentication</h3>
                        <p className="text-gray-600">
                            Industry-standard OAuth 2.0 protocol ensures your data is protected with enterprise-grade security.
                        </p>
                    </div>

                    {/* Feature 2 */}
                    <div className="bg-white rounded-xl p-6 shadow-md border border-gray-100">
                        <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mb-4">
                            <svg className="w-6 h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                            </svg>
                        </div>
                        <h3 className="text-xl font-bold text-gray-900 mb-2">Lightning Fast</h3>
                        <p className="text-gray-600">
                            Sign in with one click using your existing Google or Facebook account. No forms to fill.
                        </p>
                    </div>

                    {/* Feature 3 */}
                    <div className="bg-white rounded-xl p-6 shadow-md border border-gray-100">
                        <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mb-4">
                            <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                            </svg>
                        </div>
                        <h3 className="text-xl font-bold text-gray-900 mb-2">No Passwords</h3>
                        <p className="text-gray-600">
                            Never worry about remembering passwords or security breaches. Let Google and Facebook handle it.
                        </p>
                    </div>
                </div>

                {/* Tech Stack */}
                <div className="mt-20 bg-white rounded-xl p-8 shadow-md border border-gray-100">
                    <h2 className="text-2xl font-bold text-center text-gray-900 mb-8">Built With Modern Technologies</h2>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                        <div className="text-center">
                            <div className="text-4xl mb-2">⚛️</div>
                            <p className="font-semibold text-gray-900">React</p>
                            <p className="text-sm text-gray-600">Frontend</p>
                        </div>
                        <div className="text-center">
                            <div className="text-4xl mb-2">🟢</div>
                            <p className="font-semibold text-gray-900">Node.js</p>
                            <p className="text-sm text-gray-600">Backend</p>
                        </div>
                        <div className="text-center">
                            <div className="text-4xl mb-2">🍃</div>
                            <p className="font-semibold text-gray-900">MongoDB</p>
                            <p className="text-sm text-gray-600">Database</p>
                        </div>
                        <div className="text-center">
                            <div className="text-4xl mb-2">🔐</div>
                            <p className="font-semibold text-gray-900">OAuth 2.0</p>
                            <p className="text-sm text-gray-600">Authentication</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Home;