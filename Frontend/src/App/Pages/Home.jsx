// eslint-disable-next-line no-unused-vars
import React from 'react';
import JobSearch from '../Components/JobSearch';
import EmployerDashboard from '../Components/EmployerDashboard';
import OverView from '../JobSeeker/OverView';

const Home = () => {
    const user = JSON.parse(localStorage.getItem('user_profile')) ?? null;

    return (
        <div>
            {user?.user_role === "job seeker" ? (
                <>
                    <OverView />
                    <JobSearch />
                </>
            ) : user?.user_role === "employer" ? (
                <EmployerDashboard />
            ) : (
                <div className='capitalize'>No user role defined {user.user_role}</div>
            )}
        </div>
    );
}

export default Home;
