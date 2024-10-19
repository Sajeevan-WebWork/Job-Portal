// eslint-disable-next-line no-unused-vars
import React from 'react';
import { useEffect, useState } from 'react';
import { Avatar, Button, Chip, IconButton, Input, Option, Select, Typography } from '@material-tailwind/react';
import { MapPin, Search } from 'lucide-react';
import { Link } from 'react-router-dom';
import SpinnerLoading from './SpinnerLoading';
import toast from 'react-hot-toast';

const JobSearch = () => {
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedCategory, setSelectedCategory] = useState('');
    const [jobData, setData] = useState([]); // Initialize as an empty array
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const user = JSON.parse(localStorage.getItem('user_profile')) ?? null;

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

    // Filter jobs based on search term and selected category
    const filteredJobs = jobData.filter((job) => {
        const matchesSearch = job.title.toLowerCase().includes(searchTerm.toLowerCase()) || job.companyName.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesCategory = selectedCategory ? job.qualifications.skills.includes(selectedCategory) : true;
        return matchesSearch && matchesCategory;
    });


    const AddToFave = async (id) => {
        const jobToUpdate = jobData.find((job) => job.id === id);
        if (jobToUpdate) {
            const updatedFavStatus = !jobToUpdate.fav;

            try {
                const response = await fetch(`http://localhost:3000/job-post/${id}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ ...jobToUpdate, fav: updatedFavStatus }),
                });

                if (!response.ok) {
                    toast.success("Failed to update favorite status");
                    throw new Error('Failed to update favorite status');
                } else {
                    toast.success(" Favorite status updated")
                }

                setData((prevData) =>
                    prevData.map((job) =>
                        job.id === id ? { ...job, fav: updatedFavStatus } : job
                    )
                );
            } catch (error) {
                console.error(error.message);
                setError(error.message);
            }
        }
    };




    return (
        <div>
            {user.user_role === "job seeker" && (
                <>
                    <div className="flex flex-col md:flex-row items-center justify-center gap-8 md:gap-4 px-4 p-4 bg-white shadow-xl rounded-xl">
                        <div className="flex gap-4 flex-1 items-center md:border-r-2 w-full md:pr-4">
                            <Input
                                label="Search Jobs"
                                size='lg'
                                icon={<Search />}
                                className='text-base text-black w-full'
                                placeholder="Job Title or Company"
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                            />
                        </div>

                        <div className="flex-1 w-full">
                            <Select label="Select Category" size='lg' onChange={(e) => setSelectedCategory(e)}>
                                <Option value="">All Categories</Option>
                                <Option value="JavaScript">JavaScript</Option>
                                <Option value="React">React</Option>
                                <Option value="Node.js">Node.js</Option>
                                <Option value="UI/UX Design">UI/UX Design</Option>
                            </Select>
                        </div>
                    </div>

                    {loading ? (
                        <SpinnerLoading />
                    ) : error ? (
                        <div>Error: {error}</div>
                    ) : (
                        <>
                            <Typography className='mt-8' variant='lead'>Recently Added</Typography>
                            <div className="grid grid-cols-1 sm:grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mt-2 bg-white px-2 py-4 md:p-4">
                                {filteredJobs.length > 0 ? (
                                    filteredJobs.map((item, index) => (
                                        <div className="py-6 px-4 border-2 rounded-md border-gray-100 hover:border-theme-100 hover:shadow-lg duration-500 transition-all" key={index}>
                                            <div className="flex gap-3 justify-between items-start">
                                                <div className="flex gap-3 items-center">
                                                    <Avatar src={item.profileImage} alt="job profile" size='lg' />
                                                    <div className="flex flex-col gap-2 items-start">
                                                        <h3 className='text-lg font-semibold'>{item.companyName}</h3>
                                                        <div className='flex items-center gap-2 text-base text-gray-700 font-semibold'>
                                                            <MapPin size={18} />
                                                            {item.location}
                                                        </div>
                                                    </div>
                                                </div>

                                                {/* onClick={() => AddToFave(item.id)}  */}
                                                <IconButton onClick={() => AddToFave(item.id)} variant='text' size='sm'>
                                                    {item.fav ? (
                                                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#3354f4" className="size-6">
                                                            <path d="m11.645 20.91-.007-.003-.022-.012a15.247 15.247 0 0 1-.383-.218 25.18 25.18 0 0 1-4.244-3.17C4.688 15.36 2.25 12.174 2.25 8.25 2.25 5.322 4.714 3 7.688 3A5.5 5.5 0 0 1 12 5.052 5.5 5.5 0 0 1 16.313 3c2.973 0 5.437 2.322 5.437 5.25 0 3.925-2.438 7.111-4.739 9.256a25.175 25.175 0 0 1-4.244 3.17 15.247 15.247 0 0 1-.383.219l-.022.012-.007.004-.003.001a.752.752 0 0 1-.704 0l-.003-.001Z" />
                                                        </svg>
                                                    ) : (
                                                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="size-6">
                                                            <path strokeLinecap="round" strokeLinejoin="round" d="M21 8.25c0-2.485-2.099-4.5-4.688-4.5-1.935 0-3.597 1.126-4.312 2.733-.715-1.607-2.377-2.733-4.313-2.733C5.1 3.75 3 5.765 3 8.25c0 7.22 9 12 9 12s9-4.78 9-12Z" />
                                                        </svg>
                                                    )}
                                                </IconButton>

                                            </div>

                                            <div className="flex flex-col gap-4 mt-6">
                                                <h1 className='text-xl font-semibold'>{item.title}</h1>
                                                <div className="flex flex-col gap-6">
                                                    <div className="flex items-center gap-4">
                                                        <small className='text-sm font-normal'>Full Time</small>
                                                        <span className="w-[6px] h-[6px] rounded-full bg-gray-600"></span>
                                                        <small className='text-sm font-normal'>{item.salaryRange}</small>
                                                    </div>
                                                    <div className="flex items-center justify-between gap-4">
                                                        <div className="flex items-center gap-4">
                                                            <small className='text-sm font-normal'>Opening:</small>
                                                            <Chip value={item.opening} size='sm' className='bg-transparent text-black text-xs'></Chip>
                                                        </div>
                                                        <Link to={`/dashboard/job-details/${item.id}`}>
                                                            <Button size='sm' className='text-theme-500 border-theme-500' variant='outlined'>View Job</Button>
                                                        </Link>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    ))
                                ) : (
                                    <p>No jobs found for the search criteria.</p>
                                )}
                            </div>
                        </>
                    )}
                </>
            )}
        </div>
    );
};

export default JobSearch;
