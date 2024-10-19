import { Button, Card, Typography } from '@material-tailwind/react';
import { Plus } from 'lucide-react';
import React from 'react'
import { AddJobPost } from './AddJobPost';

const TABLE_HEAD = ["S:No", "Name of the Post", "No of Vacancy", "Application Received"];
const TABLE_ROWS = [
    {
        name: "Manager",
        noOfVacancy: 5,
        applicationReceived: 10,
    },
    {
        name: "Software Engineer",
        noOfVacancy: 8,
        applicationReceived: 20,
    },
    {
        name: "Marketing Executive",
        noOfVacancy: 3,
        applicationReceived: 15,
    },
    {
        name: "Data Analyst",
        noOfVacancy: 4,
        applicationReceived: 12,
    },
    {
        name: "HR Coordinator",
        noOfVacancy: 2,
        applicationReceived: 8,
    },
];


const EmployerDashboard = () => {
    return (
        <div className='mb-10'>
            <div className="block">
                <div className="flex items-center justify-between py-3 md:p-1">
                    <h3 className="text-lg font-semibold capitalize">Application Statistics</h3>
                    {/* <Button className='flex items-center gap-2 bg-theme-800'> <Plus size={18} className='font-bold' />Add Job</Button> */}
                    <AddJobPost />
                </div>

                <div className="py-4 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 items-center justify-between gap-4">
                    <div className="bg-white p-4 flex-1 rounded-lg shadow-sm ">
                        <Typography className='text-theme-700' variant='h3'>32</Typography>
                        <Typography variant='h6'>Total Job Post</Typography>
                    </div>

                    <div className="bg-white p-4 flex-1 rounded-lg shadow-sm ">
                        <Typography className='text-theme-700' variant='h3'>45</Typography>
                        <Typography variant='h6'>Total Application</Typography>
                    </div>

                    <div className="bg-white p-4 flex-1 rounded-lg shadow-sm ">
                        <Typography className='text-theme-700' variant='h3'>13</Typography>
                        <Typography variant='h6'>Full-Time Roles</Typography>
                    </div>
                </div>
            </div>
            <Card className="h-full w-full overflow-scroll p-0">
                <table className="w-full min-w-max table-auto p-0 text-left">
                    <thead>
                        <tr>
                            {TABLE_HEAD.map((head) => (
                                <th
                                    key={head}
                                    className="border-b border-blue-gray-100 bg-blue-gray-50 p-4"
                                >
                                    <Typography
                                        variant="small"
                                        color="blue-gray"
                                        className="font-normal leading-none opacity-70"
                                    >
                                        {head}
                                    </Typography>
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {TABLE_ROWS.map(({ name, noOfVacancy, applicationReceived }, index) => {
                            const isLast = index === TABLE_ROWS.length - 1;
                            const classes = isLast ? "p-4" : "p-4 border-b border-blue-gray-50";

                            return (
                                <tr key={name}>
                                    <td className={classes}>
                                        <Typography>{index + 1}</Typography>
                                    </td>
                                    <td className={classes}>
                                        <Typography variant="small" color="blue-gray" className="font-normal" > {name} </Typography>
                                    </td>
                                    <td className={classes}>
                                        <Typography variant="small" color="blue-gray" className="font-normal" > {noOfVacancy} </Typography>
                                    </td>
                                    <td className={classes}>
                                        <Typography variant="small" color="blue-gray" className="font-normal" > {applicationReceived} </Typography>
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </Card>
        </div>
    )
}

export default EmployerDashboard
