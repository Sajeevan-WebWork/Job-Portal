import { Typography } from '@material-tailwind/react';
// eslint-disable-next-line no-unused-vars
import React from 'react'


const WelcomeBoard = () => {
  
  const user = JSON.parse(localStorage.getItem('user_profile')) ?? null;

  return (
    <div>
      <Typography variant='h1' className='text-5xl font-bold text-center capitalize'>
          {user.user_name} Welcome to the Textile Department
        </Typography>
    </div>
  )
}

export default WelcomeBoard