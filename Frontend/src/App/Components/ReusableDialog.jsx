/* eslint-disable react/prop-types */
// eslint-disable-next-line no-unused-vars
import React from "react";
import {
    Button,
    Dialog,
    DialogHeader,
    DialogBody,
    DialogFooter,
} from "@material-tailwind/react";

export function ReusableDialog({
    open,
    handleOpen,
    title = "Dialog Title",
    body = "Dialog Body",
    cancelText = "Cancel",
    confirmText = "Confirm",
    onConfirm,
    children,
    bodyStyle = "",
    headerStyle = "",
    size = "md", // Default size is medium
}) {
    return (
        <>
            <Dialog open={open}  size={size}>
                <DialogHeader className={headerStyle}>{title}</DialogHeader>
                <DialogBody className={bodyStyle}>
                    {children ? children : body}
                </DialogBody>
                <DialogFooter>
                    <Button
                        variant="text"
                        color="red"
                        onClick={handleOpen}
                        className="mr-1"
                    >
                        <span>{cancelText}</span>
                    </Button>
                    <Button
                        variant="gradient"
                        color="green"
                        onClick={onConfirm || handleOpen}
                    >
                        <span>{confirmText}</span>
                    </Button>
                </DialogFooter>
            </Dialog>
        </>
    );
}
