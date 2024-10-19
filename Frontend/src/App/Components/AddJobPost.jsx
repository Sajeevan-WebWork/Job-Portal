/* eslint-disable no-unused-vars */
import React from "react";
import {
    Input,
    Option,
    Select,
    Button,
    Dialog,
    IconButton,
    Typography,
    DialogBody,
    DialogHeader,
    DialogFooter,
} from "@material-tailwind/react";
import { Plus, X } from "lucide-react";

export function AddJobPost() {
    const [open, setOpen] = React.useState(false);

    const handleOpen = () => setOpen(!open);

    return (
        <>
            <Button onClick={handleOpen} className="flex bg-theme-800 font-normal text-base capitalize items-center gap-1">
                <Plus /> Add Job
            </Button>
            <Dialog size="md" open={open} className="p-4">
                <DialogHeader className="relative m-0 block">
                    <Typography variant="h4" color="blue-gray">Add Job Post</Typography>
                    <IconButton size="sm" variant="text" className="!absolute right-3.5 top-3.5" onClick={handleOpen} >
                        <X className="h-4 w-4 stroke-2" />
                    </IconButton>
                </DialogHeader>
                <DialogBody className="space-y-4 pb-6">
                    <div>
                        <Typography variant="small" color="blue-gray" className="mb-2 text-left font-medium" > Job Title </Typography>
                        <Input color="gray" size="lg" placeholder="eg. Textile mills op.." name="name" className="placeholder:opacity-100 focus:!border-t-gray-900" containerProps={{ className: "!min-w-full", }} labelProps={{ className: "hidden", }} />
                    </div>


                    <div className="flex flex-col md:flex-row gap-4">
                        <div className="w-full">
                            <Typography variant="small" color="blue-gray" className="mb-2 text-left font-medium" > Total number of vacancies </Typography>
                            <Input color="gray" size="lg" placeholder="eg. 33" name="name" className="placeholder:opacity-100 focus:!border-t-gray-900" containerProps={{ className: "!min-w-full", }} labelProps={{ className: "hidden", }} />
                        </div>

                        <div className="w-full">
                            <Typography variant="small" color="blue-gray" className="mb-2 text-left font-medium" > Educational Qulification Need </Typography>
                            <Input color="gray" size="lg" placeholder="eg. 33" name="name" className="placeholder:opacity-100 focus:!border-t-gray-900" containerProps={{ className: "!min-w-full", }} labelProps={{ className: "hidden", }} />
                        </div>
                    </div>
                    <div className="flex flex-col md:flex-row gap-4">
                        <div className="w-full">
                            <Typography variant="small" color="blue-gray" className="mb-2 text-left font-medium" > Salary Expection </Typography>
                            <Input color="gray" size="lg" placeholder="eg. <8.8oz | 250g" name="weight" className="placeholder:opacity-100 focus:!border-t-gray-900" containerProps={{ className: "!min-w-full", }} labelProps={{ className: "hidden", }} />
                        </div>
                        <div className="w-full">
                            <Typography variant="small" color="blue-gray" className="mb-2 text-left font-medium" > Location </Typography>
                            <Input color="gray" size="lg" placeholder="eg. US 8" name="size" className="placeholder:opacity-100 focus:!border-t-gray-900" containerProps={{ className: "!min-w-full", }} labelProps={{ className: "hidden", }} />
                        </div>
                    </div>

                    <div className="flex flex-col md:flex-row gap-4">
                        <div className="w-full">
                            <Typography variant="small" color="blue-gray" className="mb-2 text-left font-medium" > Post (Sector Wise) </Typography>
                            <Input color="gray" size="lg" placeholder="eg. <8.8oz | 250g" name="weight" className="placeholder:opacity-100 focus:!border-t-gray-900" containerProps={{ className: "!min-w-full", }} labelProps={{ className: "hidden", }} />
                        </div>
                        <div className="w-full">
                            <Typography variant="small" color="blue-gray" className="mb-2 text-left font-medium" > Technical Qulification Needed </Typography>
                            <Input color="gray" size="lg" placeholder="eg. US 8" name="size" className="placeholder:opacity-100 focus:!border-t-gray-900" containerProps={{ className: "!min-w-full", }} labelProps={{ className: "hidden", }} />
                        </div>
                    </div>
                    <Button className="" color="blue" variant="text">Post Job</Button>
                </DialogBody>
                {/* <DialogFooter>
                    <Button className="ml-auto " onClick={handleOpen}>
                        Add Product
                    </Button>
                </DialogFooter> */}
            </Dialog>
        </>
    );
}