/* eslint-disable no-unused-vars */
import { Typography } from '@material-tailwind/react';
import { BellRing, BriefcaseBusiness, Heart } from 'lucide-react';
import React, { useEffect, useState } from 'react'
import CountUp from 'react-countup';
const user = JSON.parse(localStorage.getItem('user_profile')) ?? null;

const OverView = () => {

    const [loading, setLoading] = useState(true);
    const [jobData, setData] = useState([]); // Initialize as an empty array
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            setLoading(true);
            try {
                const response = await fetch('http://localhost:3000/job-post');
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                const result = await response.json();
                setData(result);
            } catch (error) {
                setError(error.message); // Store error message
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, []);
    return (
        <div>
            <div className="flex flex-col gap-4 pb-6">
                <div className='capitalize flex gap-1'>
                    <Typography variant='h2'>
                        Hello,
                    </Typography>
                    <Typography variant='h2' className='text-theme-500'>
                        {user && (
                            user.name
                        )}
                    </Typography>
                </div>

                <p className='text-base'>Here is your daily activites and job alerts</p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mb-10">
                <div className="flex items-center justify-between cursor-pointer  bg-purple-50 shadow-md transition-all hover:shadow-lg rounded-lg px-6 py-4">
                    <div className="flex flex-col gap-2">
                        <Typography variant='h3' className='text-theme-900 font-bold'>
                            <CountUp end={jobData.length} />
                        </Typography>

                        <Typography className='font-medium'>
                            Total Jobs
                        </Typography>
                    </div>

                    <div className="flex items-center justify-center p-4 bg-white rounded-xl">
                        <BriefcaseBusiness size={30} className='text-theme-500' />
                    </div>
                </div>

                <div className="flex items-center justify-between cursor-pointer bg-green-100 shadow-md transition-all hover:shadow-lg rounded-lg px-6 py-4">
                    <div className="flex flex-col gap-2">
                        <Typography variant='h3' className='text-theme-900 font-bold'>
                            <CountUp end={33} />
                        </Typography>

                        <Typography className='font-medium'>
                            Favorite Jobs
                        </Typography>
                    </div>

                    <div className="flex items-center justify-center p-4 bg-white rounded-xl">
                        <Heart size={30} className='text-green-500' />
                    </div>
                </div>

                <div className="flex items-center justify-between cursor-pointer bg-orange-50 shadow-md transition-all hover:shadow-lg rounded-lg px-6 py-4">
                    <div className="flex flex-col gap-2">
                        <Typography variant='h3' className='text-theme-900 font-bold'>
                            <CountUp end={323} />
                        </Typography>

                        <Typography className='font-medium'>
                            Jobs Alerts
                        </Typography>
                    </div>

                    <div className="flex items-center justify-center p-4 bg-white rounded-xl">
                        <BellRing size={30} className='text-orange-500' />
                    </div>
                </div>
            </div>
        </div>
    )
}

export default OverView
