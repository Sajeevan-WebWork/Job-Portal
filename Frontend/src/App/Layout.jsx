// eslint-disable-next-line no-unused-vars
import React from 'react'
import { Outlet } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'

const Layout = () => {
  return (
    <>
    <div className="bg[#94affc] w-full pb-10">
      <Outlet />
    </div>
      <Toaster
        position="top-center"
        reverseOrder={false}
        gutter={18}
        containerClassName=""
        containerStyle={{}}
        toastOptions={{
          // Define default options
          className: 'w-full max-w-max text-md',
          duration: 5000,
          style: {
            background: '#254b54',
            color: '#fff',
          },

          // Default options for specific types
          success: {
            duration: 5000,
            theme: {
              primary: '#254b54',
              secondary: '#254b54',
            },
          },
        }}
      />
    </>
  )
}

export default Layout
