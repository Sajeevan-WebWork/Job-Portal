/* eslint-disable react/prop-types */
// eslint-disable-next-line no-unused-vars
import React, { useState } from 'react';

const InputField = ({ inputlabel, labeValue, type, Style, defaultValue, inputParam, required }) => {
    const [value, setValue] = useState(defaultValue || ''); // Manage input value with state
    const [error, setError] = useState(''); // Error message

    // Handle change
    const handleChange = (e) => {
        setValue(e.target.value);

        // Clear error on change
        if (error) {
            setError('');
        }
    };

    // Validate on blur (when the input loses focus)
    const handleBlur = () => {
        if (required && !value) {
            setError(`${inputlabel} is required`);
        }
    };

    return (
        <div>
            <div className="relative w-full">
                <input
                    type={type}
                    id={labeValue}
                    value={value}
                    onChange={handleChange}
                    onBlur={handleBlur}  // Validate on blur
                    name={inputParam}
                    className={`block px-2.5 py-4 w-full text-base md:text-base font-normal text-gray-900 bg-transparent rounded-md border-2 ${error ? 'border-red-500' : 'border-slate-300'} appearance-none focus:outline-none focus:ring-0 ${error ? 'focus:border-red-500' : 'focus:border-theme-600'} peer ${Style}`}
                    placeholder=" "
                    required={required}
                />
                <label
                    htmlFor={labeValue}
                    className={`absolute capitalize text-base font-normal text-gray-500 duration-300 transform left-2 -translate-y-4 scale-75 top-2 z-10 origin-[0] bg-white px-2 ${error ? 'text-red-500 peer-focus:text-red-600' : 'peer-focus:text-theme-600 text-gray-500'} peer-placeholder-shown:scale-100 peer-placeholder-shown:-translate-y-1/2 peer-placeholder-shown:top-1/2 peer-focus:top-2 peer-focus:scale-75 peer-focus:-translate-y-4`}
                >
                    {inputlabel} {required && <sup className="text-red-500">*</sup>}
                </label>
            </div>

            {/* Display error message only when error exists */}
            
            <span className={`text-red-500 text-xs h-4 opacity-0 block ml-1 ${error ? "opacity-100" : "opacity-0"}`}>{error}</span>


        </div>
    );
};

export default InputField;
