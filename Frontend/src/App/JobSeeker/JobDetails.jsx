// eslint-disable-next-line no-unused-vars
import React, { useState, useEffect } from 'react';
import { Link, useParams } from 'react-router-dom';
import SpinnerLoading from '../Components/SpinnerLoading';
import { Avatar, Button, Chip, IconButton, Option, Select, Textarea, Tooltip, Typography } from '@material-tailwind/react';
import { BriefcaseBusiness, Calendar, CalendarArrowUp, ChevronLeft, CircleUserRound, Clock5, GraduationCap, MapPin, WalletMinimal } from 'lucide-react';
import { ReusableDialog } from '../Components/ReusableDialog';

const JobDetails = () => {
  const { id } = useParams();
  const [jobData, setJobData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const handleOpen = () => setDialogOpen(!dialogOpen);


  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const response = await fetch('http://localhost:3000/job-post');
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        const result = await response.json();
        setJobData(result);
      } catch (error) {
        setError(error.message);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const job = jobData.find((job) => job.id === id);


  return (
    <div>
      {/* Check if loading */}
      {loading ? (
        <SpinnerLoading />
      ) : error ? (
        <SpinnerLoading />
      ) : !job ? (
        <h2>Job not found</h2>
      ) : (
        // Render the job details once data is fetched
        <>
          <Link to={'/dashboard'} className="flex items-center gap-1 mb-4 w-max ">
            <Button variant='text' className='flex items-center font-bold text-theme-500 text-base gap-2' size='sm' color='blue' >
              <ChevronLeft size={18} />
              <span>Back</span>
            </Button>
          </Link>

          <div className="bg-white rounded-lg shadow-lg p-4">

            <div className="flex flex-col md:flex-row lg:items-center gap-4 justify-between">
              <div className="flex items-center gap-4">
                <Avatar src={job.profileImage} alt="job profile" size='lg' />
                <div className="flex flex-wrap items-center gap-1 sm:gap-4">
                  <Typography variant='h6'>{job.title}</Typography>
                  <Chip size="sm" color='blue' variant='outlined' value={job.type} className='capitalize text-sm font-semibold text-pink-500 border-pink-500' />
                </div>
              </div>

              <div className="flex gap-3 items-center">

                <div className="">
                  {job.fav ? (
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#3354f4" className="size-8">
                      <path d="m11.645 20.91-.007-.003-.022-.012a15.247 15.247 0 0 1-.383-.218 25.18 25.18 0 0 1-4.244-3.17C4.688 15.36 2.25 12.174 2.25 8.25 2.25 5.322 4.714 3 7.688 3A5.5 5.5 0 0 1 12 5.052 5.5 5.5 0 0 1 16.313 3c2.973 0 5.437 2.322 5.437 5.25 0 3.925-2.438 7.111-4.739 9.256a25.175 25.175 0 0 1-4.244 3.17 15.247 15.247 0 0 1-.383.219l-.022.012-.007.004-.003.001a.752.752 0 0 1-.704 0l-.003-.001Z" />
                    </svg>
                  ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="size-8">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M21 8.25c0-2.485-2.099-4.5-4.688-4.5-1.935 0-3.597 1.126-4.312 2.733-.715-1.607-2.377-2.733-4.313-2.733C5.1 3.75 3 5.765 3 8.25c0 7.22 9 12 9 12s9-4.78 9-12Z" />
                    </svg>
                  )}
                </div>
                <Button onClick={handleOpen} className='rounded-md bg-theme-700 w-max'>Apply Now</Button>
              </div>
            </div>

            <div className="flex items-start gap-4 my-4 flex-col md:flex-row">
              <div className="w-full md:w-4/6">
                <h4 className='text-lg font-semibold pb-4'>Job Description</h4>
                <p className='text-base text-justify'>{job.description}</p>
              </div>

              <div className="w-full md:w-2/6 border-theme-200  border-2 rounded-lg grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-3 gap-y-8 gap-x-4 py-6 px-4">
                <div className="flex flex-col gap-1">
                  <Calendar className='text-theme-600' />
                  <small className='text-sm py-1 capitalize'>Job Posted:</small>
                  <p className='text-sm'><b>{job.JobPosted || "Not Mentioned"}</b></p>
                </div>

                <div className="flex flex-col gap-1">
                  <Clock5 className='text-theme-600' />
                  <small className='text-sm py-1 capitalize'>Job expire in:</small>
                  <p className='text-sm'><b>{job.expirein || "Not Mentioned"}</b></p>
                </div>

                <div className="flex flex-col gap-1">
                  <GraduationCap className='text-theme-600' />
                  <small className='text-sm py-1 capitalize'>Education:</small>
                  <Tooltip animate={{
                    mount: { scale: 1, y: 0 },
                    unmount: { scale: 0, y: 25 },
                  }} content={job.qualifications.education || "Not Mentioned"}>
                    <p className='text-sm truncate'><b>{job.qualifications.education || "Not Mentioned"}</b></p>
                  </Tooltip>
                </div>


                <div className="flex flex-col gap-1">
                  <WalletMinimal className='text-theme-600' />
                  <small className='text-sm py-1 capitalize'>Salery:</small>
                  <p className='text-sm truncate capitalize'><b>{job.salaery || "Not Mentioned"}/month</b></p>
                </div>

                <div className="flex flex-col gap-1">
                  <MapPin className='text-theme-600' />
                  <small className='text-sm py-1 capitalize'>location:</small>
                  <p className='text-sm truncate'><b>{job.location || "Not Mentioned"}</b></p>
                </div>

                <div className="flex flex-col gap-1">
                  <BriefcaseBusiness className='text-theme-600' />
                  <small className='text-sm py-1 capitalize'>job type:</small>
                  <p className='text-sm truncate'><b>{job.type || "Not Mentioned"}</b></p>
                </div>

                <div className="flex flex-col gap-1">
                  <CalendarArrowUp className='text-theme-600' />
                  <small className='text-sm py-1 capitalize'>Experience:</small>
                  <p className='text-sm truncate'><b>{job.qualifications.experience || "Not Mentioned"}</b></p>
                </div>


                <div className="flex flex-col gap-1">
                  <CircleUserRound className='text-theme-600' />
                  <small className='text-sm py-1 capitalize'>Opening Count:</small>
                  <p className='text-sm truncate'><b>{job.opening || "Not Mentioned"}</b></p>
                </div>

              </div>
            </div>
          </div>





          {/* Comfiramtion Modal  */}
          <ReusableDialog
            open={dialogOpen}
            bodyStyle={'text-center  text-lg text-black'}
            headerStyle={''}
            size={'sm'}
            handleOpen={handleOpen}
            title={`Apply Job: ${job.title}`}
            body={
              <div className="flex flex-col items-start gap-3">
                <div className="flex flex-1 w-full flex-col gap-2 items-start">
                  <label htmlFor="selectResume" className='text-base font-semibold'>Choose Resume</label>
                  <Select label="Choose Resume" id='selectResume' className='items-start text-center' size='lg'>
                    <Option>Material Tailwind HTML</Option>
                    <Option>Material Tailwind React</Option>
                    <Option>Material Tailwind Vue</Option>
                    <Option>Material Tailwind Angular</Option>
                    <Option>Material Tailwind Svelte</Option>
                  </Select>
                </div>

                <div className="flex flex-col items-start w-full gap-2">
                  <label htmlFor="CoverLetter" id='CoverLetter' className='text-base font-semibold'>Cover Letter</label>
                  <Textarea placeholder='Write down your biography here. Let the employers know who you are...' />
                </div>


              </div>
            }
            cancelText="cancel"
            confirmText="Confirm" />
        </>
      )}
    </div>
  );
};

export default JobDetails;
