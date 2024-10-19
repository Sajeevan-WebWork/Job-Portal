/* eslint-disable no-unused-vars */
import React, { useState } from 'react';
import { Link, Outlet, useNavigate } from 'react-router-dom';
import { Button, Badge, IconButton, Avatar, Dialog, DialogHeader, DialogBody, DialogFooter, } from "@material-tailwind/react";
import { Bell, LogOut, MessageCircle, AlignJustify, UserPen, X } from 'lucide-react';
import Profile from '../../../public/profile.jpg';
import { Sidebar } from '../Components/Sidebar';
import toast from 'react-hot-toast';
import { ReusableDialog } from '../Components/ReusableDialog';


const Dashboard = () => {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false); // Manage sidebar open state

  const openDrawer = () => setOpen(true);
  const closeDrawer = () => setOpen(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const handleOpen = () => setDialogOpen(!dialogOpen);

  const userLogOut = () => {
    toast('Successfully logged out! We’re grateful for your visit. Thank you!', {
      icon: '😊',
    });
    localStorage.removeItem('loggedIn');
    localStorage.removeItem('user_profile');
    navigate('/');
  };

  const user = JSON.parse(localStorage.getItem('user_profile')) ?? null;
  

  return (
    <>
      <div className="my-2 mx-auto mb-0 w-[calc(100%-0.5rem)] md:w-[calc(100%-1.5rem)] flex justify-center">
        <div className="flex items-center justify-between rounded-2xl  w-full py-2 px-4 bg-white  shadow-sm md:shadow-sm z-20">
          <div className="flex items-center gap-3">
            <IconButton onClick={openDrawer} className='text-teal-800 bg-transparent shadow-none hover:shadow-sm' size='sm'>
              {!open ? (
                <AlignJustify className='bg-transparent' size={26} />
              ) : (
                <X />
              )}
            </IconButton>
            <Link to={'/'}>
              <h3 className="text-xl font-semibold capitalize hidden md:block hover:text-theme-900">{user.user_role}</h3>
            </Link>
          </div>

          <div className="flex items-center gap-8">
            <div className='flex items-center gap-6'>
              <Badge content="5" className='bg-theme-500'>
                <IconButton className='bg-theme-50 hover:bg-theme-100 rounded-full p-0 text-theme-950 shadow-none hover:shadow-sm'>
                  <MessageCircle />
                </IconButton>
              </Badge>
              <Badge content="1" className='bg-theme-500'>
                <IconButton className='bg-theme-50 hover:bg-theme-100 rounded-full text-theme-950 shadow-none hover:shadow-sm'>
                  <Bell />
                </IconButton>
              </Badge>

              <IconButton onClick={handleOpen} className='bg-transparent text-theme-700 shadow-none hover:shadow-sm'>
                <LogOut />
              </IconButton>
            </div>

            <Link to={'/dashboard/user-profile'}>
              <Button className='bg-transparent p-0'><Avatar src={Profile} alt="avatar" size='md' withBorder={true} color='green' /></Button>
            </Link>
          </div>
        </div>
      </div>

      <div className="container m-auto pt-3 md:pt-[2rem] px-2 md:px-0">
        <Outlet />
      </div>

      <Sidebar open={open} closeSidebar={closeDrawer} />

      <ReusableDialog
        open={dialogOpen}
        bodyStyle={'text-center  text-lg text-black'}
        headerStyle={'justify-center'} size={'sm'}
        handleOpen={handleOpen}
        title="Please Confirm"
        body="Are you sure you want to log out?"
        cancelText="cancel"
        confirmText="Confirm"
        onConfirm={userLogOut} />
    </>
  );
};

export default Dashboard;
