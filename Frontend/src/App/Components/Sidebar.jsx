/* eslint-disable react/prop-types */
/* eslint-disable no-unused-vars */
import React, { useState } from 'react';
import toast from 'react-hot-toast';
import { Card, List, ListItem, ListItemPrefix, IconButton, Drawer, ListItemSuffix, Chip, } from "@material-tailwind/react";
import { LayoutDashboard, ShoppingCart, Inbox, UserPen, Settings, LogOut, X, FileUser, Briefcase, UserPlus } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { ReusableDialog } from './ReusableDialog';

export const Sidebar = ({ open, closeSidebar }) => {
    const navigate = useNavigate();
    const [dialogOpen, setDialogOpen] = useState(false);
    const handleOpen = () => setDialogOpen(!dialogOpen);

    const userLogOut = () => {
        toast('Successfully logged out! We’re grateful for your visit. Thank you!', {
            icon: '👏',
        });
        localStorage.removeItem('loggedIn');
        localStorage.removeItem('user_profile');
        navigate('/');
    };

    const user = JSON.parse(localStorage.getItem('user_profile')) ?? null;

    return (
        <>
            <Drawer open={open} onClose={closeSidebar}>
                <div className="p-6 flex items-center justify-between">
                    <img src="../../../public/Textile-black-logo.png" className='w-40' alt="Textile Logo" />
                    <IconButton variant="text" color="blue-gray" onClick={closeSidebar}>
                        <X />
                    </IconButton>
                </div>

                <Card className="h-[calc(100vh-2rem)] w-full shadow-none">
                    <List onClick={closeSidebar}>

                        <Link to={'/dashboard'}>
                            <ListItem> <ListItemPrefix> <LayoutDashboard /> </ListItemPrefix> Dashboard </ListItem>
                        </Link>
                        {/* this profile nav is for Job Seeker */}
                        <Link to={'/dashboard/user-profile'}>
                            <ListItem> <ListItemPrefix> <UserPen /> </ListItemPrefix> Profile </ListItem>
                        </Link>


                        {/* this Inbox nav is for Job Seeker */}
                        <ListItem> <ListItemPrefix> <Inbox /> </ListItemPrefix> Inbox
                            <ListItemSuffix>
                                <Chip value="14" size="sm" variant="ghost" color="blue" className="rounded-full" />
                            </ListItemSuffix>
                        </ListItem>

                        {user.user_role === "job seeker" && (
                            <>
                                <ListItem> <ListItemPrefix> <FileUser /> </ListItemPrefix> Application History </ListItem>
                                <ListItem> <ListItemPrefix> <Briefcase /> </ListItemPrefix> Vacant position </ListItem>
                            </>
                        )}

                        {user.user_role === "employer" && (
                            <>
                                <ListItem className='capitalize'> <ListItemPrefix> <Briefcase /> </ListItemPrefix> job seeker Request </ListItem>
                                <ListItem className='capitalize'> <ListItemPrefix> <UserPlus /> </ListItemPrefix> New recruitment </ListItem>
                            </>
                        )}

                        <ListItem onClick={handleOpen}> <ListItemPrefix> <LogOut /> </ListItemPrefix> Log Out </ListItem>
                    </List>
                </Card>
            </Drawer>


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