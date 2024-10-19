import { Spinner } from '@material-tailwind/react'
import React from 'react'

const SpinnerLoading = () => {
    return (
        <div>
            <div className="h-screen flex items-center justify-center backdrop-blur-sm absolute inset-0 m-auto z-20">
                <Spinner className="h-12 w-12 text-theme-500 " />
            </div>
        </div>
    )
}

export default SpinnerLoading
