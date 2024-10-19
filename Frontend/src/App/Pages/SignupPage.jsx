/* eslint-disable no-unused-vars */
// eslint-disable-next-line no-unused-vars
import React, { useState } from 'react'
import Logo from '../../../public/Textile-black-logo.png'
import { Link, useNavigate } from 'react-router-dom'
import InputField from '../Components/InputField'
import { ChevronDown } from 'lucide-react'
import JobSeekerForm from '../Components/JobSeekerForm'
import toast, { Toaster } from 'react-hot-toast';



const SignupPage = () => {

    const [activeTab, setActiveTab] = useState('jobSeeker');
    const [errorMessage, setErrorMessage] = useState('');
    const [loading, setLoading] = useState(false);

    const navigate = useNavigate(); // Use to navigate to another page

    const handleTabClick = (tab) => {
        setActiveTab(tab);
    };


    const handleSubmit = async (event) => {
        event.preventDefault();
        setLoading(true);
        // setErrorMessage('');

        const formData = new FormData(event.target);
        const data = Object.fromEntries(formData.entries());
        console.log(data);

        try {
            const response = await fetch('http://localhost:3000/user', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            });

            // Parse the JSON response
            const result = await response.json();

            // Check if the status code is 201 (Created)
            if (response.status === 201) {
                const user = JSON.stringify(result)
                toast.success('Your Job Portal Account Created successfully')
                event.target.reset(); // Reset the form after successful signup
                setLoading(false); // Stop loading state
                navigate('/login'); // Redirect to dashboard or another page after signup
            } else {
                throw new Error(result.message || 'Failed to create user');
            }
        } catch (error) {
            toast.error('signup error:', error)
            event.target.reset(); // Reset the form after successful signup
            console.error('signup error:', error);
            setLoading(false); // Stop loading state
        }
    };


    const [toggleStates, setToggleStates] = useState({
        physicallyHandicapped: false,
        workingExperience: false,
        povertyStatus: false,
    });

    const handleCheckboxChange = (name) => {
        const newState = !toggleStates[name];
        setToggleStates((prev) => ({
            ...prev,
            [name]: newState,
        }));

        // Update workingExperience based on the toggle
        if (name === 'workingExperience') {
            setWorkingExperience(newState ? 'Yes' : 'No');
        }
    };

    const [workingExperience, setWorkingExperience] = useState('No');


    return (
        <>
            <div className="max-w-3xl md:py-4 w-full flex items-center justify-center m-auto pb-10 hidden">
                <JobSeekerForm />
            </div>
            <div className='max-w-4xl md:py-4 w-full flex items-center justify-center m-auto pb-10'>
                <div className="flex items-center gap-[5rem] rounded-md  justify-center relative md:px-5 w-full">
                    <div className="flex flex-1 justify-center bg-white w-full flex-col md:border-2 smd:hadow-lg rounded-2xl items-center gap-2 p-5 md:p-5 ">
                        <div className="m-auto  py-2">
                            <img src={Logo} alt="logo" className='w-52' />
                        </div>
                        <h1 className="text-2xl md:text-3xl text-theme-500 font-semibold ">Create Your Account</h1>
                        {/* <p className="text-sm font-normal text-teal-900  py-4">Let’s get you all st up so you can access your personal account</p> */}

                        <div className="flex items-center gap-2 md:gap-4  my-4 flex-wrap justify-center">
                            <div className="text-base font-bold whitespace-nowrap">I&apos;m a :</div>
                            <ul className="flex flex-wrap justify-center text-sm font-medium text-center text-gray-500 border-b border-gray-200">
                                <li className="me-2">
                                    <a href="#" className={`inline-block transition-all p-2 text-gray-700 text-sm font-semibold rounded-t-lg ${activeTab === 'jobSeeker' ? 'text-theme-600 bg-theme-100 active' : 'hover:text-gray-900 hover:bg-theme-50'}`} onClick={() => handleTabClick('jobSeeker')} > Job Seeker </a>
                                </li>
                                <li className="me-2">
                                    <a href="#" className={`inline-block transition-all p-2 text-gray-700 text-sm font-semibold rounded-t-lg ${activeTab === 'employer' ? 'text-theme-600 bg-theme-100 active' : 'hover:text-gray-900 hover:bg-theme-50'}`} onClick={() => handleTabClick('employer')} > Employer </a>
                                </li>
                                <li className="me-2">
                                    <a href="#" className={`inline-block transition-all p-2 text-gray-700 text-sm font-semibold rounded-t-lg ${activeTab === 'trainingSeeker' ? 'text-theme-600 bg-theme-100 active' : 'hover:text-gray-900 hover:bg-theme-50'}`} onClick={() => handleTabClick('trainingSeeker')} > Training Seeker </a>
                                </li>
                                <li className="me-2">
                                    <a href="#" className={`inline-block transition-all p-2 text-gray-700 text-sm font-semibold rounded-t-lg ${activeTab === 'trainingAgencies' ? 'text-theme-600 bg-theme-100 active' : 'hover:text-gray-900 hover:bg-theme-50'}`} onClick={() => handleTabClick('trainingAgencies')} > Training Agencies </a>
                                </li>
                            </ul>
                        </div>

                        {/* <h2 className="text-xl font-semibold">Job Seeker</h2> */}
                        <div className="flex flex-col gap-2 md:gap-4  w-full">
                            <form action="post" onSubmit={handleSubmit} id='jobmanager' className="flex flex-col gap-2 md:gap-4">

                                <div className='opacity-0 hidden'>
                                    {activeTab === "jobSeeker" ? (
                                        // <h5 className='text-base capitalize font-semibold'>Job Seeker</h5>
                                        <input type="text" name="user_role" value={'job seeker'} />
                                    ) : activeTab === "employer" ? (
                                        // <h5 className='text-base capitalize font-semibold'>Employer</h5>
                                        <input type="text" name="user_role" value={'employer'} />
                                    ) : activeTab === "trainingSeeker" ? (
                                        // <h5 className='text-base capitalize font-semibold'>training Seeker</h5>
                                        <input type="text" name="user_role" value={'training seeker'} />
                                    ) : activeTab === "trainingAgencies" ? (
                                        // <h5 className='text-base capitalize font-semibold'>training Agencies</h5>
                                        <input type="text" name="user_role" value={'training agencies'} />

                                    ) : null}
                                </div>

                                <div className="grid md:grid-cols-2 gap-2 md:gap-4">
                                <InputField required={true} inputParam={'user_name'} type={'text'} labeValue={'newId'} inputlabel={'create a new ID'} />
                                <InputField required={true} inputParam={'password'} type={'password'} labeValue={'new_password'} inputlabel={'create a password'} />
                                </div>

                                <div className="grid md:grid-cols-2 gap-x-4 gap-y-2 md:gap-y-4">
                                    {(activeTab === 'jobSeeker' || activeTab === 'trainingSeeker') && (
                                        <>
                                            <InputField inputParam={'name'} type={'text'} labeValue={'name'} inputlabel={'Name'} required={true} />
                                            <InputField inputParam={'dob'} type={'date'} labeValue={'DOB'} inputlabel={'Date of Birth'} Style={'h-[60px]'} required={true}  />
                                            <InputField inputParam={'age'} type={'number'} labeValue={'age'} inputlabel={'Age'} required={true} />
                                            <InputField inputParam={'nationality'} type={'text'} labeValue={'nationality'} inputlabel={'Nationality'} required={true} />
                                        </>
                                    )}


                                    {activeTab === 'employer' && (
                                        <>
                                            <InputField required={true} inputParam={'company_name'} type={'text'} labeValue={'company_name'} inputlabel={'name of the company'} />
                                            <InputField required={true} inputParam={'business_nature'} type={'text'} labeValue={'business_nature'} inputlabel={'nature of the business'} />
                                            <InputField required={true} inputParam={'establishment_year'} type={'text'} labeValue={'establishment_year'} inputlabel={'Year of establishment'} />
                                            <InputField required={true} inputParam={'gst_number'} type={'text'} labeValue={'gst_number'} inputlabel={'GST Number'} />
                                        </>
                                    )}
                                </div>


                                {(activeTab === 'jobSeeker' || activeTab === 'trainingSeeker') && (
                                    <>
                                        <div className="grid align-middle sm:grid-cols-2 gap-2 md:gap-4 items-center">
                                            <div className='relative'>
                                                <select id="usergender" name='user_gender' required className="block px-2.5 pb-3 pt-3 w-full text-base text-gray-500 bg-transparent rounded-md border-2 border-slate-300 appearance-none focus:outline-none focus:ring-0 focus:border-theme-600 peer">
                                                    <option required selected>Choose a Gender</option>
                                                    <option value="Male">Male</option>
                                                    <option value="Female">Female</option>
                                                    <option value="Others">Others</option>
                                                </select>

                                                <span className='absolute top-4 right-4'><ChevronDown /></span>
                                                <span className="h-4 block"></span>
                                            </div>

                                            <InputField inputParam={'mobile_number'} type={'number'} labeValue={'mobilenumber'} inputlabel={'Mobile number'} required={true} />
                                        </div>

                                    </>
                                )}

                                <div className={`grid gap-x-4 ${activeTab === 'employer' ? "grid-cols-2" : "grid-cols-1"}`}>
                                    {activeTab === "employer" && (
                                        <InputField required={true} inputParam={'registration_number'} type={'text'} labeValue={'registration-number'} inputlabel={'Registration Number'} />
                                    )}
                                    <InputField required={true} inputParam={'address'} type={'text'} labeValue={'address'} inputlabel={'address'} />

                                </div>

                                {activeTab === "employer" && (
                                    <>
                                        <InputField required={true} inputParam={'contact_person_name'} type={'text'} labeValue={'contact_person_name'} inputlabel={'contact person name'} />
                                        <InputField required={true} inputParam={'contact_person_number'} type={'text'} labeValue={'contact_person_number'} inputlabel={'contact person name number'} />
                                        <InputField required={true} inputParam={'unitdetails'} type={'text'} labeValue={'unitdetails'} inputlabel={'if any additional unit details'} />
                                        <div className="grid grid-cols-1 md:grid-cols-3 gap-2 md:gap-4">
                                            <InputField required={true} inputParam={'works_number'} type={'text'} labeValue={'works_number'} inputlabel={'Number of works'} />
                                            <InputField required={true} inputParam={'Town'} type={'text'} labeValue={'Town'} inputlabel={'Mention Town'} />
                                            <InputField required={true} inputParam={'District_name'} type={'text'} labeValue={'District_name'} inputlabel={'District name'} />
                                        </div>

                                        {/* <div className="grid grid-cols-1 md:grid-cols-2 gap-2 md:gap-4">
                                            
                                        </div> */}
                                    </>
                                )}



                                {(activeTab === 'jobSeeker' || activeTab === 'trainingSeeker') && (
                                    <>
                                        <InputField required={true} inputParam={'emailAddress'} type={'email'} labeValue={'emailAddress'} inputlabel={'Email Address'} />

                                        <div className="grid items-center align-middle sm:grid-cols-3 gap-2 md:gap-4">
                                            <InputField required={true} inputParam={'idproof'} type={'text'} labeValue={'idproof'} inputlabel={'ID Card No'} />
                                            <InputField required={true} inputParam={'community'} type={'text'} labeValue={'community'} inputlabel={'Community'} />
                                            <InputField required={true} inputParam={'educationqualification'} type={'text'} labeValue={'educationqualification'} inputlabel={'Education Qualification'} />
                                        </div>

                                        <div className="flex flex-col md:flex-row md:items-center gap-3 md:gap-4 flex-wrap justify-between">

                                            <div className="flex flex-1 flex-col gap-3 border-2 px-3 py-1 rounded-lg">
                                                <p className="font-medium text-sm">Below the Poverty Line</p>

                                                <label className='themeSwitcherTwo relative inline-flex cursor-pointer select-none items-center'>
                                                    <input
                                                        type='checkbox'
                                                        checked={toggleStates.povertyStatus}
                                                        onChange={() => handleCheckboxChange('povertyStatus')}
                                                        className='sr-only'
                                                    />
                                                    <span className='label flex items-center text-sm font-medium text-black'> NO </span>
                                                    <span className={`slider mx-4 flex h-8 w-[60px] items-center rounded-full p-1 duration-200 ${toggleStates.povertyStatus ? 'bg-theme-500' : 'bg-gray-400'}`}>
                                                        <span className={`dot h-6 w-6 rounded-full bg-white duration-200 ${toggleStates.povertyStatus ? 'translate-x-[28px]' : ''}`}></span>
                                                    </span>
                                                    <span className='label flex items-center text-sm font-medium text-black uppercase'> Yes </span>
                                                    <input type="hidden" value={toggleStates.povertyStatus ? 'Yes' : 'No'} name="poverty_status" />
                                                </label>
                                            </div>

                                            <div className="flex flex-1 flex-col gap-3 border-2 px-3 py-1 rounded-lg">
                                                <p className="font-medium text-sm">Physically Handicapped</p>

                                                <label className='themeSwitcherTwo relative inline-flex cursor-pointer select-none items-center'>
                                                    <input
                                                        type='checkbox'
                                                        checked={toggleStates.physicallyHandicapped}
                                                        onChange={() => handleCheckboxChange('physicallyHandicapped')}
                                                        className='sr-only'
                                                    />
                                                    <span className='label flex items-center text-sm font-medium text-black'> NO </span>
                                                    <span className={`slider mx-4 flex h-8 w-[60px] items-center rounded-full p-1 duration-200 ${toggleStates.physicallyHandicapped ? 'bg-theme-500' : 'bg-gray-400'}`}>
                                                        <span className={`dot h-6 w-6 rounded-full bg-white duration-200 ${toggleStates.physicallyHandicapped ? 'translate-x-[28px]' : ''}`}></span>
                                                    </span>
                                                    <span className='label flex items-center text-sm font-medium text-black uppercase'> Yes </span>
                                                    <input type="hidden" value={toggleStates.physicallyHandicapped ? 'Yes' : 'No'} name="physically_handicapped" />
                                                </label>
                                            </div>

                                            {activeTab === "jobSeeker" && (
                                                <div className="flex flex-1 flex-col gap-3 border-2 px-3 py-1 rounded-lg mb-2">
                                                    <p className="font-medium text-sm">Working Experience</p>

                                                    <label className='themeSwitcherTwo relative inline-flex cursor-pointer select-none items-center'>
                                                        <input
                                                            type='checkbox'
                                                            checked={toggleStates.workingExperience}
                                                            onChange={() => handleCheckboxChange('workingExperience')}
                                                            className='sr-only'
                                                        />
                                                        <span className='label flex items-center text-sm font-medium text-black'> NO </span>
                                                        <span className={`slider mx-4 flex h-8 w-[60px] items-center rounded-full p-1 duration-200 ${toggleStates.workingExperience ? 'bg-theme-500' : 'bg-gray-400'}`}>
                                                            <span className={`dot h-6 w-6 rounded-full bg-white duration-200 ${toggleStates.workingExperience ? 'translate-x-[28px]' : ''}`}></span>
                                                        </span>
                                                        <span className='label flex items-center text-sm font-medium text-black uppercase'> Yes </span>
                                                        <input type="hidden" value={toggleStates.workingExperience ? 'Yes' : 'No'} name="working_experience" />
                                                    </label>
                                                </div>
                                            )}

                                        </div>

                                        {workingExperience === 'Yes' && (
                                            <InputField required={true} inputParam={'experience_years'} type={'number'} labeValue={'experience-years'} inputlabel={'Number of years'} />
                                        )}

                                        <div className='grid gap-2 md:gap-4'>
                                            <InputField required={true} inputParam={'textilesector'} type={'text'} labeValue={'textilesector'} inputlabel={'Textile sector to be trained'} />

                                            {activeTab === "trainingSeeker" && (
                                                <InputField required={true} inputParam={'agencydetails'} type={'text'} labeValue={'agencydetails'} inputlabel={'Implementation agency details'} />
                                            )}

                                            {activeTab === "jobSeeker" && (
                                                <InputField required={true} inputParam={'preferred_post'} type={'text'} labeValue={'preferred-post'} inputlabel={'Preferred for the post'} />
                                            )}

                                            {activeTab === 'jobSeeker' && (

                                                <div>
                                                    <label className="block mb-1 text-sm font-medium text-gray-900" htmlFor="file_input">Certificate Upload</label>
                                                    <input required={true} name='certificate' accept='application/msword, application/vnd.ms-excel, application/vnd.ms-powerpoint, text/plain, application/pdf,/*' className="block p-2 w-full text-sm text-gray-900 border border-gray-300 rounded-lg cursor-pointer bg-gray-50" id="file_input" type="file" />
                                                </div>
                                            )}
                                        </div>

                                        {activeTab === 'jobSeeker' && (

                                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 md:gap-4">
                                                <InputField required={true} inputParam={'salary_expectation'} type={'text'} labeValue={'salary-expectation'} inputlabel={'Salary Expectation'} />
                                                <div className='relative'>
                                                    <select id="countries" required name='perferred_district' className="block px-2.5 pb-3 pt-3 w-full text-base text-gray-500 bg-transparent rounded-md border-2 border-slate-300 appearance-none focus:outline-none focus:ring-0 focus:border-theme-600 peer">
                                                        <option selected value={''}>Preferred District</option>
                                                        <option value="District-1">District-1</option>
                                                        <option value="District-2">District-2</option>
                                                        <option value="District-3">District-3</option>
                                                    </select>

                                                    <span className='absolute top-4 right-4'><ChevronDown /></span>
                                                </div>
                                            </div>
                                        )}
                                    </>
                                )}



                                <button type='submit' className='bg-theme-500 py-4 md:py-3 px-8 my-8 rounded-md text-white text-lg md:text-base font-medium shadow-sm hover:shadow-md transition-all' disabled={loading}>
                                    {loading ? (
                                        <>
                                            <svg aria-hidden="true" role="status" className="inline mr-3 w-[1.4rem] h-[1.4rem] text-white bg-transparent animate-spin" viewBox="0 0 100 101" fill="none" xmlns="http://www.w3.org/2000/svg">
                                                <path d="M100 50.5908C100 78.2051 77.6142 100.591 50 100.591C22.3858 100.591 0 78.2051 0 50.5908C0 22.9766 22.3858 0.59082 50 0.59082C77.6142 0.59082 100 22.9766 100 50.5908ZM9.08144 50.5908C9.08144 73.1895 27.4013 91.5094 50 91.5094C72.5987 91.5094 90.9186 73.1895 90.9186 50.5908C90.9186 27.9921 72.5987 9.67226 50 9.67226C27.4013 9.67226 9.08144 27.9921 9.08144 50.5908Z" fill="#E5E7EB"></path>
                                                <path d="M93.9676 39.0409C96.393 38.4038 97.8624 35.9116 97.0079 33.5539C95.2932 28.8227 92.871 24.3692 89.8167 20.348C85.8452 15.1192 80.8826 10.7238 75.2124 7.41289C69.5422 4.10194 63.2754 1.94025 56.7698 1.05124C51.7666 0.367541 46.6976 0.446843 41.7345 1.27873C39.2613 1.69328 37.813 4.19778 38.4501 6.62326C39.0873 9.04874 41.5694 10.4717 44.0505 10.1071C47.8511 9.54855 51.7191 9.52689 55.5402 10.0491C60.8642 10.7766 65.9928 12.5457 70.6331 15.2552C75.2735 17.9648 79.3347 21.5619 82.5849 25.841C84.9175 28.9121 86.7997 32.2913 88.1811 35.8758C89.083 38.2158 91.5421 39.6781 93.9676 39.0409Z" fill="#FFF"></path>
                                            </svg>
                                            Loading...
                                        </>
                                    ) : (
                                        'Create account'
                                    )}
                                </button>
                                {/* <button type='submit' className='bg-theme-500 py-3 rounded-md text-white text-base font-medium shadow-sm hover:shadow-md transition-all'>Create account</button> */}
                                <div className="flex gap-2 justify-center text-sm items-center">Already have an account?  <Link to={'/login'} className="text-theme-500 font-bold cursor-pointer hover:text-theme-800 uppercase">Login</Link></div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </>
    )
}

export default SignupPage