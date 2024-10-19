import React from 'react'

// eslint-disable-next-line react/prop-types
const CustomButton = ({ onClick, text }) => {
    return (
        <button onClick={onClick}>
            {text}
        </button>
    )
}

export default CustomButton
