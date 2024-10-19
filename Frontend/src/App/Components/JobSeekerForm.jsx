import React from 'react'
import { Input } from "@material-tailwind/react";


const JobSeekerForm = () => {
    return (
        <div>
            <div className="flex flex-col gap-2 md:gap-4">
                <Input className='border-theme-800 border-2' name='user_name' color='teal' label="Username" size='lg' />
            </div>
        </div>
    )
}

export default JobSeekerForm
