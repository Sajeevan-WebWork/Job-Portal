import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import LogInPage from './App/Pages/LogInPage.jsx';
import SignupPage from './App/Pages/SignupPage.jsx';
import Dashboard from './App/Pages/Dashboard.jsx';
import JobListing from './App/Pages/JobListing.jsx';
import ForgotPassword from './App/Pages/ForgotPassword.jsx';
import './index.css';
import AuthRoutes from './utils/AuthRoutes.jsx';
import { ThemeProvider } from "@material-tailwind/react"
import Layout from './App/Layout.jsx';
import WelcomeBoard from './App/Components/WelcomeBoard.jsx';
import UserProfile from './App/Pages/UserProfile.jsx';
import Home from './App/Pages/Home.jsx';
import JobDetails from './App/JobSeeker/JobDetails.jsx';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ThemeProvider>
      <Router>
        <Routes>
          {/* Use the AuthRoutes component to handle both public and protected routes */}
          <Route element={<AuthRoutes />}>
            <Route element={<Layout />} >
              <Route path='/' element={<LogInPage />} />
              <Route path='/login' element={<LogInPage />} />
              <Route path='/signup' element={<SignupPage />} />
              <Route path='/forgot-password' element={<ForgotPassword />} />

              {/* Dashboard route with nested routes */}
              <Route path='/dashboard' element={<Dashboard />}>
                <Route index element={<Home />} /> {/* Default route for dashboard */}
                <Route path='user-profile' element={<UserProfile />} /> {/* Relative path */}
                <Route path='user-welcome' element={<WelcomeBoard />} /> {/* Relative path */}
                <Route path='job-details/:id' element={<JobDetails />} /> {/* Relative path */}
              </Route>

              <Route path='/job-listing' element={<JobListing />} />
              <Route path='/user-profile' element={<UserProfile />} />
              {/* <Route path="*" element={<Navigate to="/" />} /> */}

            </Route>
          </Route>
        </Routes>
      </Router>
    </ThemeProvider>
  </StrictMode>
);

