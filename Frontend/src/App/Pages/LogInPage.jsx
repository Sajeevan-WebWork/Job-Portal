/* eslint-disable no-unused-vars */
import React, { useState } from 'react';
import Logo from '../../../public/Textile-black-logo.png';
import { Link, useNavigate } from 'react-router-dom';
import InputField from '../Components/InputField';
import toast, { Toaster } from 'react-hot-toast';


const LogInPage = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const navigate = useNavigate(); // Use to navigate to another page

  // Handle form submission
  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);

    const formData = new FormData(event.target);
    const data = Object.fromEntries(formData.entries());

    try {
      const response = await fetch('http://localhost:3000/user'); // GET is default method
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }

      const result = await response.json();
      let userFound = false; // Flag to check if user is found

      for (let i = 0; i < result.length; i++) {
        const user = result[i];

        const isValidUser = data.user_name === user.user_name && data.password === user.password;

        if (isValidUser) {
          toast.success('Successfully logged in! Thank you for choosing us!', {
            icon: '✅',
          });
          localStorage.setItem('user_profile', JSON.stringify(user));

          // alert('You Logged In Successfully');
          localStorage.setItem("loggedIn", 'true');
          event.target.reset();
          setLoading(false);
          navigate('/dashboard');
          userFound = true; // Set flag to true when user is found
          break; // Exit the loop
        }
      }

      if (!userFound) {
        toast.error('Invalid Username or password');
        setLoading(false);
      }

    } catch (error) {
      toast.error('Error', error.message)
      setLoading(false); // Ensure loading state is reset on error
    } finally {
      setLoading(false);
    }
  }



  return (
    <div className="max-w-lg w-full flex items-center justify-center h-screen m-auto">
      {/* <pre>{JSON.stringify(data, null, 2)}</pre> */}
      <div className="flex items-center gap-[5rem]  rounded-md justify-center relative md:px-5 w-full">
        <div className="flex flex-1 justify-center bg-white w-full flex-col md:border-2 rounded-2xl md:shadow-lg shadow-theme-500 items-center gap-2 px-5 md:p-6 h-screen  md:h-auto">
          <div className="md:m-auto py-5">
            <img src={Logo} alt="logo" className="w-52" />
          </div>
          <h1 className="text-2xl text-theme-500 font-semibold flex items-center">Welcome Back!</h1>
          <p className="text-sm font-normal text-teal-900 py-4">
            Login to access your Job Portal account
          </p>
          <div className="flex flex-col gap-4 w-full">
            <form action="post" onSubmit={handleSubmit} className="flex flex-col gap-5">
              <div className="flex flex-col gap-5 md:gap-6">
                <InputField
                  inputParam={'user_name'}
                  type={'text'}
                  labeValue={'userName'}
                  inputlabel={'User Name'}
                  required={true}
                />
                <InputField
                  inputParam={'password'}
                  type={'password'}
                  labeValue={'password'}
                  inputlabel={'Password'}
                  required={true}
                />
              </div>
              <div className="text-sm text-red-500 self-end cursor-pointer hover:text-red-700">
                Forgot Password
              </div>

              <button
                type="submit"
                className="bg-theme-500 py-4 md:py-3 px-8 my-2 rounded-md text-white text-lg md:text-base font-medium shadow-sm hover:shadow-md transition-all"
                disabled={loading}
              >
                {loading ? (
                  <>
                    <svg
                      aria-hidden="true"
                      role="status"
                      className="inline mr-3 w-[1.4rem] h-[1.4rem] text-white bg-transparent animate-spin"
                      viewBox="0 0 100 101"
                      fill="none"
                      xmlns="http://www.w3.org/2000/svg"
                    >
                      <path
                        d="M100 50.5908C100 78.2051 77.6142 100.591 50 100.591C22.3858 100.591 0 78.2051 0 50.5908C0 22.9766 22.3858 0.59082 50 0.59082C77.6142 0.59082 100 22.9766 100 50.5908ZM9.08144 50.5908C9.08144 73.1895 27.4013 91.5094 50 91.5094C72.5987 91.5094 90.9186 73.1895 90.9186 50.5908C90.9186 27.9921 72.5987 9.67226 50 9.67226C27.4013 9.67226 9.08144 27.9921 9.08144 50.5908Z"
                        fill="#E5E7EB"
                      ></path>
                      <path
                        d="M93.9676 39.0409C96.393 38.4038 97.8624 35.9116 97.0079 33.5539C95.2932 28.8227 92.871 24.3692 89.8167 20.348C85.8452 15.1192 80.8826 10.7238 75.2124 7.41289C69.5422 4.10194 63.2754 1.94025 56.7698 1.05124C51.7666 0.367541 46.6976 0.446843 41.7345 1.27873C39.2613 1.69328 37.813 4.19778 38.4501 6.62326C39.0873 9.04874 41.5694 10.4717 44.0505 10.1071C47.8511 9.54855 51.7191 9.52689 55.5402 10.0491C60.8642 10.7766 65.9928 12.5457 70.6331 15.2552C75.2735 17.9648 79.3347 21.5619 82.5849 25.841C84.9175 28.9121 86.7997 32.2913 88.1811 35.8758C89.083 38.2158 91.5421 39.6781 93.9676 39.0409Z"
                        fill="#FFF"
                      ></path>
                    </svg>
                    Loading...
                  </>
                ) : (
                  'Login'
                )}
              </button>

              {errorMessage && <div className="text-red-500 text-sm">{errorMessage}</div>}

              <div className="flex gap-2 justify-center text-sm items-center">
                Don’t have an account?{' '}
                <Link to={'/signup'} className="text-theme-500 font-bold cursor-pointer hover:text-theme-800 uppercase">
                  Sign up
                </Link>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LogInPage;
