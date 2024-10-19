import { Avatar, Typography, Button } from "@material-tailwind/react";
import Profile from '../../../public/profile.jpg';
import { Pencil } from "lucide-react";
import SpinnerLoading from "../Components/SpinnerLoading";

const UserProfile = () => {
  // Retrieve user data from localStorage and parse it
  const user = JSON.parse(localStorage.getItem('user_profile')) ?? null;

  return (
    <>
      {user ? (
        <div className="flex flex-col w-full shadow-sm rounded-md">
          <div className="flex items-center bg-white p-4 rounded-lg shadow-lg justify-between w-full">
            <div className="flex gap-2 items-center">
              <Avatar src={Profile} alt="avatar" size='lg' withBorder={true} color='green' />
              <div className="flex flex-col items-start gap-2">
                <Typography className=" capitalize text-sm font-semibold">{user.user_name}</Typography>
                <Typography className={` capitalize text-xs font-bold rounded-md 
                ${user.user_role === "job seeker" ? "text-blue-900" :
                    user.user_role === "employer" ? "text-green-900" :
                      user.user_role === "training seeker" ? "text-yellow-900" :
                        user.user_role === "training agencies" ? "text-red-900" : "text-gray-500" // Default color
                  }`
                }>
                  {user.user_role}
                </Typography>

              </div>
            </div>
            <Button className="bg-theme-900 capitalize text-sm flex gap-2 items-center"><Pencil size={16} /> Edit</Button>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 bg-white p-4 rounded-lg shadow-blue-gray-100 shadow-lg gap-8 my-6">

            {user.name && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Name</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.name}</small>
              </div>
            )}

            {user.dob && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Date of Birth:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.dob}</small>
              </div>
            )}
            {user.age && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Age:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.age}</small>
              </div>
            )}
            {user.nationality && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Nationality:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.nationality}</small>
              </div>
            )}
            {user.user_gender && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Gender:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.user_gender}</small>
              </div>
            )}
            {user.mobile_number && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Mobile Number:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.mobile_number}</small>
              </div>
            )}

            {user.emailAddress && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Email:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.emailAddress}</small>
              </div>
            )}
            {user.idproof && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">ID Proof:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.idproof}</small>
              </div>
            )}
            {user.community && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Community:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.community}</small>
              </div>
            )}
            {user.educationqualification && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Education Qualification:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.educationqualification}</small>
              </div>
            )}
            {user.poverty_status && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Poverty Status:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.poverty_status}</small>
              </div>
            )}
            {user.physically_handicapped && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Physically Handicapped:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.physically_handicapped}</small>
              </div>
            )}
            {user.working_experience && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Working Experience:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.working_experience}</small>
              </div>
            )}
            {user.experience_years && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Experience Years:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.experience_years}</small>
              </div>
            )}
            {user.textilesector && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Textile Sector:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.textilesector}</small>
              </div>
            )}

            {user.salary_expectation && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Salary Expectation:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.salary_expectation}</small>
              </div>

            )}
            {user.preferred_district && (
              <div className="flex flex-col gap-1">
                <strong className="capitalize">Preferred District:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.preferred_district}</small>
              </div>
            )}

            {user.company_name && (
              <div className="flex flex-col gap-1">
                <strong className="capitalize">Name of the company:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.company_name}</small>
              </div>
            )}

            {user.business_nature && (
              <div className="flex flex-col gap-1">
                <strong className="capitalize">Business Nature:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.business_nature}</small>
              </div>
            )}


            {user.contact_person_name && (
              <div className="flex flex-col gap-1">
                <strong className="capitalize">constact person name:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.contact_person_name}</small>
              </div>
            )}

            {user.contact_person_number && (
              <div className="flex flex-col gap-1">
                <strong className="capitalize">contact person number:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.contact_person_number}</small>
              </div>
            )}

            {user.address && (

              <div className="flex flex-col gap-1">
                <strong className="capitalize">Address:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.address}</small>
              </div>
            )}

            {user.establishment_year && (
              <div className="flex flex-col gap-1">
                <strong className="capitalize">establishment year:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.establishment_year}</small>
              </div>
            )}

            {user.gst_number && (
              <div className="flex flex-col gap-1">
                <strong className="capitalize">GST number:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.gst_number}</small>
              </div>
            )}

            {user.registration_number && (
              <div className="flex flex-col gap-1">
                <strong className="capitalize">registration number:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.registration_number}</small>
              </div>
            )}

            {user.unitdetails && (
              <div className="flex flex-col gap-1">
                <strong className="capitalize">unit details:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.unitdetails}</small>
              </div>
            )}

            {user.works_number && (
              <div className="flex flex-col gap-1">
                <strong className="capitalize">works number:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.works_number}</small>
              </div>
            )}

            {user.Town && (
              <div className="flex flex-col gap-1">
                <strong className="capitalize">Town:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.Town}</small>
              </div>
            )}

            {user.District_name && (
              <div className="flex flex-col gap-1">
                <strong className="capitalize">District name:</strong>
                <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">{user.District_name}</small>
              </div>
            )}

            {user.user_role === "admin" ? (
              <>
                {user?.user_name && (
                  <div className="flex flex-col gap-1">
                    <strong className="capitalize">User name:</strong>
                    <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">
                      {user.user_name}
                    </small>
                  </div>
                )}

                {user?.user_role && (
                  <div className="flex flex-col gap-1">
                    <strong className="capitalize">User Role:</strong>
                    <small className="bg-theme-50 text-base font-medium capitalize rounded-lg p-3">
                      {user.user_role}
                    </small>
                  </div>
                )}
              </>
            ) : (
              ""
            )}



          </div>
        </div>
      ) : (
        <SpinnerLoading />
      )}
    </>
  );
}

export default UserProfile;
