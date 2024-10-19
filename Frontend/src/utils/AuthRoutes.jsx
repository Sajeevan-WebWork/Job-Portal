// eslint-disable-next-line no-unused-vars
import { Outlet, Navigate, useLocation, } from 'react-router-dom';

const AuthRoutes = () => {
    const user = localStorage.getItem('loggedIn') === 'true'; // Determine if user is logged in
    const location = useLocation();

    // Define public paths
    const publicPaths = ['/login', '/', '/signup', '/forgot-password'];

    if (user && publicPaths.includes(location.pathname)) {
        return <Navigate to='/dashboard' replace={true} />;
    }

    if (!user && !publicPaths.includes(location.pathname)) {
        return <Navigate to='/login' replace={true} />;
    }

    return <Outlet />;
};

export default AuthRoutes;
